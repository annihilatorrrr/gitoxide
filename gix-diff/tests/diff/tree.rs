mod changes {
    mod to_obtain_tree {
        use std::collections::HashMap;

        use gix_diff::tree::{
            recorder,
            recorder::{Change::*, Location},
            visit::Relation,
        };
        use gix_hash::{oid, ObjectId};
        use gix_object::{bstr::ByteSlice, tree::EntryKind, TreeRefIter};
        use gix_odb::pack::Find;

        use crate::hex_to_id;

        type Changes = Vec<recorder::Change>;

        fn db(args: impl IntoIterator<Item = &'static str>) -> crate::Result<gix_odb::Handle> {
            gix_odb::at(
                gix_testtools::scripted_fixture_read_only_with_args_standalone("make_diff_repo.sh", args)?
                    .join(".git")
                    .join("objects"),
            )
            .map_err(Into::into)
        }

        fn locate_tree_by_commit<'a>(
            db: &gix_odb::Handle,
            commit: &oid,
            buf: &'a mut Vec<u8>,
        ) -> crate::Result<TreeRefIter<'a>> {
            let tree_id = db
                .try_find(commit, buf)?
                .ok_or_else(|| format!("start commit {commit:?} to be present"))?
                .0
                .decode()?
                .into_commit()
                .expect("id is actually a commit")
                .tree();

            Ok(db
                .try_find(&tree_id, buf)?
                .expect("main tree present")
                .0
                .try_into_tree_iter()
                .expect("id to be a tree"))
        }

        fn diff_commits(
            db: &gix_odb::Handle,
            lhs: impl Into<Option<ObjectId>>,
            rhs: &oid,
            location: Option<Location>,
        ) -> crate::Result<Changes> {
            let mut buf = Vec::new();
            let lhs_tree = lhs
                .into()
                .and_then(|lhs| locate_tree_by_commit(db, &lhs, &mut buf).ok());
            let mut buf2 = Vec::new();
            let rhs_tree = locate_tree_by_commit(db, rhs, &mut buf2)?;
            let mut recorder = gix_diff::tree::Recorder::default().track_location(location);
            gix_diff::tree(
                lhs_tree.unwrap_or_default(),
                rhs_tree,
                gix_diff::tree::State::default(),
                db,
                &mut recorder,
            )?;
            Ok(recorder.records)
        }

        fn diff_with_previous_commit_from(db: &gix_odb::Handle, commit_id: &oid) -> crate::Result<Changes> {
            let mut buf = Vec::new();
            let (main_tree_id, parent_commit_id) = {
                let commit = db
                    .try_find(commit_id, &mut buf)?
                    .ok_or_else(|| format!("start commit {commit_id:?} to be present"))?
                    .0
                    .decode()?
                    .into_commit()
                    .expect("id is actually a commit");

                (commit.tree(), {
                    let p = commit.parents().next();
                    p
                })
            };
            let current_tree = db
                .try_find(&main_tree_id, &mut buf)?
                .expect("main tree present")
                .0
                .try_into_tree_iter()
                .expect("id to be a tree");
            let mut buf2 = Vec::new();
            let previous_tree: Option<_> = {
                parent_commit_id
                    .and_then(|id| db.try_find(&id, &mut buf2).ok().flatten())
                    .and_then(|(c, _l)| c.decode().ok())
                    .and_then(gix_object::ObjectRef::into_commit)
                    .map(|c| c.tree())
                    .and_then(|tree| db.try_find(&tree, &mut buf2).ok().flatten())
                    .and_then(|(tree, _)| tree.try_into_tree_iter())
            };

            let mut recorder = gix_diff::tree::Recorder::default();
            gix_diff::tree(
                previous_tree.unwrap_or_default(),
                current_tree,
                &mut gix_diff::tree::State::default(),
                db,
                &mut recorder,
            )?;
            Ok(recorder.records)
        }

        fn head_of(db: &gix_odb::Handle) -> ObjectId {
            ObjectId::from_hex(
                std::fs::read(
                    db.store_ref()
                        .path()
                        .parent()
                        .unwrap()
                        .join("refs")
                        .join("heads")
                        .join("main"),
                )
                .expect("head ref")
                .as_bstr()
                .trim(),
            )
            .expect("valid hex id")
        }

        fn all_commits(db: &gix_odb::Handle) -> HashMap<String, ObjectId> {
            let mut buf = Vec::new();

            let head = head_of(db);
            gix_traverse::commit::Simple::new(Some(head), &db)
                .collect::<Result<Vec<_>, _>>()
                .expect("valid iteration")
                .into_iter()
                .map(|c| {
                    use gix_object::FindExt;
                    (
                        db.find_commit(&c.id, &mut buf)
                            .unwrap()
                            .message
                            .trim()
                            .to_str_lossy()
                            .into_owned(),
                        c.id,
                    )
                })
                .rev()
                .collect()
        }

        #[test]
        fn many_different_states() -> crate::Result {
            let db = db(None)?;
            let all_commits = all_commits(&db);
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["f added"])?,
                vec![Addition {
                    entry_mode: EntryKind::Blob.into(),
                    oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                    path: "f".into(),
                    relation: None
                }],
                ":000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A      f"
            );

            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["f modified"])?,
                vec![Modification {
                    previous_entry_mode: EntryKind::Blob.into(),
                    previous_oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                    entry_mode: EntryKind::Blob.into(),
                    oid: hex_to_id("28ce6a8b26aa170e1de65536fe8abe1832bd3242"),
                    path: "f".into()
                }],
                ":100644 100644 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 28ce6a8b26aa170e1de65536fe8abe1832bd3242 M      f"
            );

            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["f deleted"])?,
                vec![Deletion {
                    entry_mode: EntryKind::Blob.into(),
                    oid: hex_to_id("28ce6a8b26aa170e1de65536fe8abe1832bd3242"),
                    path: "f".into(),
                    relation: None
                }],
                ":100644 000000 28ce6a8b26aa170e1de65536fe8abe1832bd3242 0000000000000000000000000000000000000000 D	f
            "
            );

            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["f mode modified to dir f/"])?,
                vec![
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("28ce6a8b26aa170e1de65536fe8abe1832bd3242"),
                        path: "f".into(),
                        relation: None
                    },
                    Addition {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("10f2f4b82222d2b5c31985130979a91fd87410f7"),
                        path: "f".into(),
                        relation: Some(Relation::Parent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("28ce6a8b26aa170e1de65536fe8abe1832bd3242"),
                        path: "f/f".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    }
                ],
                ":100644 000000 28ce6a8b26aa170e1de65536fe8abe1832bd3242 0000000000000000000000000000000000000000 D      f
                   :000000 100644 0000000000000000000000000000000000000000 28ce6a8b26aa170e1de65536fe8abe1832bd3242 A      f/f"
            );

            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["a renamed to b"])?,
                vec![
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "a".into(),
                        relation: None
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "b".into(),
                        relation: None
                    }
                ],
                "simple rename, same level
                 :100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D      a
                 :000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A      b"

            );

            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["f/f modified"])?,
                vec![
                    Modification {
                        previous_entry_mode: EntryKind::Tree.into(),
                        previous_oid: hex_to_id("10f2f4b82222d2b5c31985130979a91fd87410f7"),
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("ebbe0b3000afdfd1aed15000094b59a2800328eb"),
                        path: "f".into()
                    },
                    Modification {
                        previous_entry_mode: EntryKind::Blob.into(),
                        previous_oid: hex_to_id("28ce6a8b26aa170e1de65536fe8abe1832bd3242"),
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("13c2aca72ab576cb5f22dc8e7f8ba8ddab553a8a"),
                        path: "f/f".into()
                    },
                ],
                ":100644 100644 28ce6a8b26aa170e1de65536fe8abe1832bd3242 13c2aca72ab576cb5f22dc8e7f8ba8ddab553a8a M	f/f"
            );

            let tree_with_link_id = hex_to_id("7e26dba59b6336f87d1d4ae3505a2da302b91c76");
            let link_entry_oid = hex_to_id("2e65efe2a145dda7ee51d1741299f848e5bf752e");
            let link_entry_mode = EntryKind::Link;
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["f/f mode changed to link"])?,
                vec![
                    Modification {
                        previous_entry_mode: EntryKind::Tree.into(),
                        previous_oid: hex_to_id("849bd76db90b65ebbd2e6d3970ca70c96ee5592c"),
                        entry_mode: EntryKind::Tree.into(),
                        oid: tree_with_link_id,
                        path: "f".into()
                    },
                    Modification {
                        previous_entry_mode: EntryKind::Blob.into(),
                        previous_oid: hex_to_id("13c2aca72ab576cb5f22dc8e7f8ba8ddab553a8a"),
                        entry_mode: link_entry_mode.into(),
                        oid: link_entry_oid,
                        path: "f/f".into()
                    },
                ],
                ":100644 120000 13c2aca72ab576cb5f22dc8e7f8ba8ddab553a8a 2e65efe2a145dda7ee51d1741299f848e5bf752e T	f/f"
            );

            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["f/ changed into file f"])?,
                vec![
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "f".into(),
                        relation: None
                    },
                    Deletion {
                        entry_mode: EntryKind::Tree.into(),
                        oid: tree_with_link_id,
                        path: "f".into(),
                        relation: Some(Relation::Parent(1))
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "f/a".into(),
                        relation: Some(Relation::ChildOfParent(1))
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "f/b".into(),
                        relation: Some(Relation::ChildOfParent(1))
                    },
                    Deletion {
                        entry_mode: link_entry_mode.into(),
                        oid: link_entry_oid,
                        path: "f/f".into(),
                        relation: Some(Relation::ChildOfParent(1))
                    },
                ],
                ":000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A	f
                 :100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D	f/a
                 :100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D	f/b
                 :120000 000000 2e65efe2a145dda7ee51d1741299f848e5bf752e 0000000000000000000000000000000000000000 D	f/f"
            );
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["delete d/"])?,
                vec![
                    Deletion {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("3d5a503f4062d198b443db5065ca727f8354e7df"),
                        path: "d".into(),
                        relation: Some(Relation::Parent(1))
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "d/f".into(),
                        relation: Some(Relation::ChildOfParent(1))
                    },
                ],
                ":100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D	d/f"
            );
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["add /c /d /e"])?,
                vec![
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "c".into(),
                        relation: None,
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "d".into(),
                        relation: None,
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "e".into(),
                        relation: None,
                    },
                ],
                ":000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A	c
                 :000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A	d
                 :000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A	e"
            );
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["add g/a"])?,
                vec![
                    Addition {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("496d6428b9cf92981dc9495211e6e1120fb6f2ba"),
                        path: "g".into(),
                        relation: Some(Relation::Parent(1))
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "g/a".into(),
                        relation: Some(Relation::ChildOfParent(1))
                    },
                ],
                ":000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A	g/a"
            );
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["remove /c /d /e"])?,
                vec![
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "c".into(),
                        relation: None
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "d".into(),
                        relation: None
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "e".into(),
                        relation: None
                    },
                ],
                ":100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D	c
                 :100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D	d
                 :100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D	e"
            );
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["rm /f, add /ff"])?,
                vec![
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "f".into(),
                        relation: None
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "ff".into(),
                        relation: None
                    },
                ],
                ":100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D	f
                  :000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A	ff"
            );
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["rm g/a, add g/aa"])?,
                vec![
                    Modification {
                        previous_entry_mode: EntryKind::Tree.into(),
                        previous_oid: hex_to_id("496d6428b9cf92981dc9495211e6e1120fb6f2ba"),
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("6e5931346904b020301f74f581142826eacc4678"),
                        path: "g".into()
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "g/a".into(),
                        relation: None
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "g/aa".into(),
                        relation: None
                    },
                ],
                ":100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D	g/a
                 :000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A	g/aa"
            );
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["rm /ff, add /f"])?,
                vec![
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "f".into(),
                        relation: None,
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "ff".into(),
                        relation: None,
                    },
                ],
                ":100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D	f
                  :000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A	ff"
            );
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["rm g/aa, add g/a"])?,
                vec![
                    Modification {
                        previous_entry_mode: EntryKind::Tree.into(),
                        previous_oid: hex_to_id("6e5931346904b020301f74f581142826eacc4678"),
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("496d6428b9cf92981dc9495211e6e1120fb6f2ba"),
                        path: "g".into()
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "g/a".into(),
                        relation: None,
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "g/aa".into(),
                        relation: None,
                    },
                ],
                ":000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A	g/a
                :100644 000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0000000000000000000000000000000000000000 D	g/aa"
            );
            Ok(())
        }

        #[test]
        fn many_different_states_nested() -> crate::Result {
            let db = db(["a"].iter().copied())?;
            let all_commits = all_commits(&db);

            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["f added"])?,
                vec![
                    Addition {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("3d5a503f4062d198b443db5065ca727f8354e7df"),
                        path: "a".into(),
                        relation: Some(Relation::Parent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "a/f".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    }
                ],
                ":000000 100644 0000000000000000000000000000000000000000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 A      a/f"
            );
            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["f modified"])?,
                vec![
                    Modification {
                        previous_entry_mode: EntryKind::Tree.into(),
                        previous_oid: hex_to_id("3d5a503f4062d198b443db5065ca727f8354e7df"),
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("10f2f4b82222d2b5c31985130979a91fd87410f7"),
                        path: "a".into()
                    },
                    Modification {
                        previous_entry_mode: EntryKind::Blob.into(),
                        previous_oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("28ce6a8b26aa170e1de65536fe8abe1832bd3242"),
                        path: "a/f".into()
                    }
                ],
                ":100644 100644 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 28ce6a8b26aa170e1de65536fe8abe1832bd3242 M      a/f"
            );

            for (_, commit) in all_commits {
                // Just make sure it works - checked results with dbg!() once and am too ~~lazy~~ time constrained to add the
                // assertions now similar to the non-nested version.
                diff_with_previous_commit_from(&db, &commit)?;
            }

            Ok(())
        }

        #[test]
        fn maximal_difference() -> crate::Result {
            let db = db(None)?;
            let all_commits = all_commits(&db);

            let last_commit = all_commits["rm g/aa, add g/a"];
            let first_commit = all_commits["f added"];
            assert_eq!(
                diff_commits(&db, first_commit.to_owned(), &last_commit, None)?,
                vec![
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "".into(),
                        relation: None
                    },
                    Addition {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("496d6428b9cf92981dc9495211e6e1120fb6f2ba"),
                        path: "".into(),
                        relation: Some(Relation::Parent(1))
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "".into(),
                        relation: Some(Relation::ChildOfParent(1))
                    }
                ]
            );
            assert_eq!(
                diff_commits(&db, last_commit.to_owned(), &first_commit, Location::FileName.into())?,
                vec![
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "b".into(),
                        relation: None
                    },
                    Deletion {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("496d6428b9cf92981dc9495211e6e1120fb6f2ba"),
                        path: "g".into(),
                        relation: Some(Relation::Parent(1))
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "a".into(),
                        relation: Some(Relation::ChildOfParent(1))
                    }
                ]
            );
            Ok(())
        }

        #[test]
        fn maximal_difference_nested() -> crate::Result {
            let db = db(["a"].iter().copied())?;
            let all_commits = all_commits(&db);

            assert_eq!(
                diff_commits(&db, None::<ObjectId>, &all_commits["add g/a"], Some(Location::Path))?,
                vec![
                    Addition {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("0df4d0ed769eacd0a231e7512fca25d3cabdeca4"),
                        path: "a".into(),
                        relation: Some(Relation::Parent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "a/b".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "a/c".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "a/d".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "a/e".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "a/f".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("496d6428b9cf92981dc9495211e6e1120fb6f2ba"),
                        path: "a/g".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "a/g/a".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    }
                ]
            );
            Ok(())
        }

        #[test]
        fn directory_rename() -> crate::Result {
            let db = db(None)?;
            let all_commits = all_commits(&db);

            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["rename git-sec to gix-sec"])?,
                vec![
                    Deletion {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("d8c30fb72173778ed57fac5813c5e37038a8746c"),
                        path: "git-sec".into(),
                        relation: Some(Relation::Parent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("d8c30fb72173778ed57fac5813c5e37038a8746c"),
                        path: "gix-sec".into(),
                        relation: Some(Relation::Parent(2)),
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "git-sec/2".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "git-sec/7".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Deletion {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("fd7938a0c18f993c89eda3f40a6d06fa6785833c"),
                        path: "git-sec/subdir".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "gix-sec/2".into(),
                        relation: Some(Relation::ChildOfParent(2)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "gix-sec/7".into(),
                        relation: Some(Relation::ChildOfParent(2)),
                    },
                    Addition {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("fd7938a0c18f993c89eda3f40a6d06fa6785833c"),
                        path: "gix-sec/subdir".into(),
                        relation: Some(Relation::ChildOfParent(2)),
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "git-sec/subdir/6".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "gix-sec/subdir/6".into(),
                        relation: Some(Relation::ChildOfParent(2)),
                    }
                ]
            );
            Ok(())
        }

        #[test]
        fn reverse_directory_rename() -> crate::Result {
            let db = db(None)?;
            let all_commits = all_commits(&db);

            assert_eq!(
                diff_with_previous_commit_from(&db, &all_commits["rename gix-sec to git-sec"])?,
                vec![
                    Addition {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("d8c30fb72173778ed57fac5813c5e37038a8746c"),
                        path: "git-sec".into(),
                        relation: Some(Relation::Parent(1)),
                    },
                    Deletion {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("d8c30fb72173778ed57fac5813c5e37038a8746c"),
                        path: "gix-sec".into(),
                        relation: Some(Relation::Parent(2)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "git-sec/2".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "git-sec/7".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Addition {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("fd7938a0c18f993c89eda3f40a6d06fa6785833c"),
                        path: "git-sec/subdir".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "gix-sec/2".into(),
                        relation: Some(Relation::ChildOfParent(2)),
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "gix-sec/7".into(),
                        relation: Some(Relation::ChildOfParent(2)),
                    },
                    Deletion {
                        entry_mode: EntryKind::Tree.into(),
                        oid: hex_to_id("fd7938a0c18f993c89eda3f40a6d06fa6785833c"),
                        path: "gix-sec/subdir".into(),
                        relation: Some(Relation::ChildOfParent(2)),
                    },
                    Addition {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "git-sec/subdir/6".into(),
                        relation: Some(Relation::ChildOfParent(1)),
                    },
                    Deletion {
                        entry_mode: EntryKind::Blob.into(),
                        oid: hex_to_id("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
                        path: "gix-sec/subdir/6".into(),
                        relation: Some(Relation::ChildOfParent(2)),
                    }
                ]
            );
            Ok(())
        }
    }
}
