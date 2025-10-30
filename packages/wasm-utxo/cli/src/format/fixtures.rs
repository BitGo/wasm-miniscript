use super::tree::{node_to_string_with_scheme, ColorScheme};
use crate::node::Node;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

/// Generate a tree representation of a Node without colors
pub fn generate_tree_text(node: &Node) -> Result<String, io::Error> {
    // Use the no-color scheme for consistent fixture output
    let no_color_scheme = ColorScheme::no_color();
    node_to_string_with_scheme(node, &no_color_scheme)
}

/// Generate a tree representation of a Node with a specific color scheme
pub fn generate_tree_text_with_scheme(
    node: &Node,
    color_scheme: &ColorScheme,
) -> Result<String, io::Error> {
    node_to_string_with_scheme(node, color_scheme)
}

/// Returns the path to the fixture directory
pub fn fixtures_directory() -> PathBuf {
    let project_dir = env::current_dir().expect("Failed to get current directory");
    project_dir.join("tests").join("fixtures")
}

/// Write tree output to a fixture file
pub fn write_fixture(name: &str, content: &str) -> Result<(), io::Error> {
    let fixtures_dir = fixtures_directory();
    fs::create_dir_all(&fixtures_dir)?;

    let fixture_path = fixtures_dir.join(format!("{}.txt", name));

    // Write the content to the file
    let mut file = fs::File::create(&fixture_path)?;
    file.write_all(content.as_bytes())?;

    Ok(())
}

/// Read the content of a fixture file if it exists
pub fn read_fixture(name: &str) -> Result<Option<String>, io::Error> {
    let fixture_path = fixtures_directory().join(format!("{}.txt", name));

    if fixture_path.exists() {
        let content = fs::read_to_string(&fixture_path)?;
        Ok(Some(content))
    } else {
        Ok(None)
    }
}

/// Ensure the generated tree output matches the fixture file
/// If the fixture doesn't exist, it will be created
pub fn assert_tree_matches_fixture(node: &Node, name: &str) -> Result<(), io::Error> {
    let generated = generate_tree_text(node)?;

    match read_fixture(name)? {
        Some(fixture_content) => {
            // Compare the generated output to the fixture
            assert_eq!(
                generated, fixture_content,
                "Generated tree output doesn't match fixture file: {}",
                name
            );
        }
        None => {
            // Create the fixture if it doesn't exist
            write_fixture(name, &generated)?;
            println!("Created new fixture: {}.txt", name);
        }
    }

    Ok(())
}

/// Force update of a fixture file with new content
pub fn update_fixture(node: &Node, name: &str) -> Result<(), io::Error> {
    let generated = generate_tree_text(node)?;
    write_fixture(name, &generated)
}

// Environment variable to force fixture updates
const UPDATE_FIXTURES_ENV: &str = "UPDATE_FIXTURES";

/// Check if fixtures should be updated
pub fn should_update_fixtures() -> bool {
    env::var(UPDATE_FIXTURES_ENV).is_ok()
}

/// Assert tree matches fixture, updating if needed or requested
pub fn assert_or_update_fixture(node: &Node, name: &str) -> Result<(), io::Error> {
    let generated = generate_tree_text(node)?;

    match read_fixture(name)? {
        Some(fixture_content) => {
            if should_update_fixtures() || generated != fixture_content {
                write_fixture(name, &generated)?;
                println!("Updated fixture: {}.txt", name);
            } else {
                assert_eq!(
                    generated, fixture_content,
                    "Generated tree output doesn't match fixture file: {}",
                    name
                );
            }
        }
        None => {
            // Create the fixture if it doesn't exist
            write_fixture(name, &generated)?;
            println!("Created new fixture: {}.txt", name);
        }
    }

    Ok(())
}
