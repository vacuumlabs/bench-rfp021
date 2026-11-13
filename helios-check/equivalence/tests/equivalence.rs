//! Unpatched Helios, patched Helios and the three steps (keys decompressed and
//! supplied) must give every update the same verdict, and leave the same store.
//!
//! `cargo test -p equivalence -- --nocapture` lists every case and its verdict.
use std::path::{Path, PathBuf};

use equivalence::*;
use helios_check_steps::Refusal;

/// Compare the two sides' records, print them, and return the verdicts.
fn compare(upstream: Vec<Record>, patched: Vec<Record>) -> Vec<Option<bool>> {
    assert_eq!(upstream.len(), patched.len());
    let mut accepted = Vec::new();
    for (u, p) in upstream.iter().zip(&patched) {
        assert_eq!(u.case, p.case);
        match u.verdicts.first() {
            Some((_, helios)) => {
                assert_eq!(p.verdicts.len(), 3, "{}: the patched side runs Helios and the three steps twice", u.case);
                for (who, verdict) in &p.verdicts {
                    assert_eq!(verdict, helios, "{}: patched {who} disagrees with unpatched Helios", u.case);
                }
                let verdict = match helios {
                    Ok(()) => "accepted".to_string(),
                    Err(e) => format!("rejected: {e}"),
                };
                println!("{verdict:<52} {}", u.case);
                accepted.push(Some(helios.is_ok()));
            }
            None => {
                println!("{:<52} {}", "forced", u.case);
                accepted.push(None);
            }
        }
        assert_eq!(u.store, p.store, "{}: the stores differ", u.case);
    }
    accepted
}

fn sync_tests(dirs: Vec<(PathBuf, String)>) {
    assert!(!dirs.is_empty());
    let mut updates = 0;
    for (dir, name) in &dirs {
        let case = SpecCase::load(dir, name.clone());
        updates += compare(upstream::spec(&case), patched::spec(&case)).iter().flatten().count();
    }
    println!("{} sync tests, {updates} updates: all four ways alike", dirs.len());
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_dir()).collect();
    out.sort();
    out
}

/// Helios's own consensus-specs sync tests (its `testdata`, Capella to Gloas).
#[test]
fn helios_sync_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../helios-patched/ethereum/consensus-core/testdata");
    let dirs = subdirs(&root)
        .iter()
        .flat_map(|fork| subdirs(fork))
        .filter(|case| case.join("steps.yaml").exists())
        .map(|case| (case.clone(), case.strip_prefix(&root).unwrap().display().to_string()))
        .collect();
    sync_tests(dirs);
}

/// The whole consensus-specs release Helios targets: scripts/fetch-spec-tests.sh,
/// then CONSENSUS_SPEC_TESTS=$PWD/target/consensus-spec-tests/tests.
#[test]
#[ignore = "set CONSENSUS_SPEC_TESTS (scripts/fetch-spec-tests.sh)"]
fn consensus_spec_sync_tests() {
    let root = PathBuf::from(std::env::var("CONSENSUS_SPEC_TESTS").expect("CONSENSUS_SPEC_TESTS"));
    let mut dirs = Vec::new();
    for fork in ["capella", "deneb", "electra", "fulu", "gloas"] {
        let forks = root.join("minimal").join(fork).join("light_client/sync/pyspec_tests");
        for case in subdirs(&forks) {
            let name = format!("{fork}/{}", case.file_name().unwrap().to_string_lossy());
            dirs.push((case, name));
        }
    }
    sync_tests(dirs);
}

/// Real mainnet updates must verify; tampered copies must not.
#[test]
fn mainnet_updates_and_tampered_copies() {
    let cases = mainnet_cases(&Fixtures::load());
    let verdicts = compare(upstream::mainnet(&cases), patched::mainnet(&cases));
    for (case, accepted) in cases.iter().zip(&verdicts) {
        assert_eq!(accepted.unwrap(), case.valid, "{}", case.name);
    }
    let valid = cases.iter().filter(|c| c.valid).count();
    println!("{valid} mainnet updates accepted, {} tampered copies rejected, all four ways alike", cases.len() - valid);
}

/// Updates re-signed with up to the most non-signers 2/3 allows must verify,
/// with keys decompressed and supplied.
#[test]
fn many_non_signers() {
    let cases = non_signer_cases(&Fixtures::load(), &Generated::default());
    let verdicts = compare(upstream::mainnet(&cases), patched::mainnet(&cases));
    for (case, accepted) in cases.iter().zip(&verdicts) {
        assert_eq!(accepted.unwrap(), case.valid, "{}", case.name);
    }
}

/// Step 1 refuses supplied keys that are not exactly the ones it needs.
#[test]
fn wrong_supplied_keys_are_refused() {
    let cases = non_signer_cases(&Fixtures::load(), &Generated::default());
    let case = cases.iter().find(|c| c.name.ends_with("re-signed with 17 non-signers")).unwrap();
    let (store, update) = (patched::store(case), patched::update(case));
    let forks = mainnet_forks();
    let step1 = |keys: &[u8]| {
        helios_check_steps::step1(&update, case.current_slot, &store, mainnet_genesis_root(), &forks, Some(keys), &|| 0).map(|_| ())
    };
    let keys = supplied_keys(&update, &store).unwrap();
    assert_eq!(step1(&keys), Ok(()), "the right keys");

    // Keys: the aggregate key, then each non-signer's.
    let mut another_members = keys.clone();
    another_members.copy_within(96..192, 192);
    let mut off_curve = keys.clone();
    off_curve[95] ^= 1;
    let mut one_too_many = keys.clone();
    one_too_many.extend_from_slice(&keys[96..192]);
    let one_too_few = keys[..keys.len() - 96].to_vec();
    let not_whole = keys[..keys.len() - 1].to_vec();
    for (what, bad) in [
        ("another member's key", another_members),
        ("a point off the curve", off_curve),
        ("one key too many", one_too_many),
        ("one key too few", one_too_few),
        ("a key cut short", not_whole),
    ] {
        match step1(&bad) {
            Err(Refusal::Keys(e)) => println!("refused {what}: {e}"),
            other => panic!("{what}: {other:?}"),
        }
    }
}
