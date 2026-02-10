//! Maven `pom.xml` 和 Gradle `gradle.lockfile` 解析器。

use std::path::Path;

use crate::{Dependency, Ecosystem, ScaError};
use super::LockfileParser;

// ---------------------------------------------------------------------------
// Maven pom.xml 解析器
// ---------------------------------------------------------------------------

pub struct MavenParser;

impl LockfileParser for MavenParser {
    fn parse(&self, content: &str, path: &Path) -> Result<Vec<Dependency>, ScaError> {
        use quick_xml::events::Event;
        use quick_xml::reader::Reader;

        let path_str = path.display().to_string();
        let mut deps = Vec::new();
        let mut reader = Reader::from_str(content);
        let mut buf = Vec::new();

        // 追蹤 XML 結構
        let mut in_dependency = false;
        let mut in_dependencies = false;
        let mut current_group_id = String::new();
        let mut current_artifact_id = String::new();
        let mut current_version = String::new();
        let mut current_tag = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag_name.as_str() {
                        "dependencies" => in_dependencies = true,
                        "dependency" if in_dependencies => {
                            in_dependency = true;
                            current_group_id.clear();
                            current_artifact_id.clear();
                            current_version.clear();
                        }
                        _ => {}
                    }
                    current_tag = tag_name;
                }
                Ok(Event::End(ref e)) => {
                    let tag_name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag_name.as_str() {
                        "dependencies" => in_dependencies = false,
                        "dependency" if in_dependency => {
                            if !current_group_id.is_empty()
                                && !current_artifact_id.is_empty()
                                && !current_version.is_empty()
                            {
                                deps.push(Dependency {
                                    name: format!("{}:{}", current_group_id, current_artifact_id),
                                    version: current_version.clone(),
                                    ecosystem: Ecosystem::Maven,
                                    lockfile_path: path_str.clone(),
                                    line: 0,
                                });
                            }
                            in_dependency = false;
                        }
                        _ => {}
                    }
                    current_tag.clear();
                }
                Ok(Event::Text(ref e)) if in_dependency => {
                    let text = e.unescape().unwrap_or_default().trim().to_string();
                    match current_tag.as_str() {
                        "groupId" => current_group_id = text,
                        "artifactId" => current_artifact_id = text,
                        "version" => current_version = text,
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ScaError::LockfileParse {
                        path: path_str,
                        reason: e.to_string(),
                    });
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(deps)
    }
}

// ---------------------------------------------------------------------------
// Gradle lockfile 解析器
// ---------------------------------------------------------------------------

pub struct GradleParser;

impl LockfileParser for GradleParser {
    fn parse(&self, content: &str, path: &Path) -> Result<Vec<Dependency>, ScaError> {
        let path_str = path.display().to_string();
        let mut deps = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            // 跳過註解和空行
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // 格式: group:artifact:version=hash
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            let coord = parts[0].trim();
            let segments: Vec<&str> = coord.split(':').collect();
            if segments.len() >= 3 {
                deps.push(Dependency {
                    name: format!("{}:{}", segments[0], segments[1]),
                    version: segments[2].to_string(),
                    ecosystem: Ecosystem::Maven,
                    lockfile_path: path_str.clone(),
                    line: 0,
                });
            }
        }

        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pom_xml() {
        let content = r#"<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>"#;

        let parser = MavenParser;
        let deps = parser.parse(content, Path::new("pom.xml")).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "org.apache.commons:commons-lang3");
        assert_eq!(deps[0].version, "3.12.0");
        assert_eq!(deps[0].ecosystem, Ecosystem::Maven);
        assert_eq!(deps[1].name, "com.google.guava:guava");
        assert_eq!(deps[1].version, "31.1-jre");
    }

    #[test]
    fn parse_gradle_lockfile() {
        let content = r#"# This is a Gradle generated file for dependency locking.
com.google.code.gson:gson:2.10.1=classpath
org.jetbrains.kotlin:kotlin-stdlib:1.9.10=classpath
"#;

        let parser = GradleParser;
        let deps = parser.parse(content, Path::new("gradle.lockfile")).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "com.google.code.gson:gson");
        assert_eq!(deps[0].version, "2.10.1");
        assert_eq!(deps[1].name, "org.jetbrains.kotlin:kotlin-stdlib");
        assert_eq!(deps[1].version, "1.9.10");
    }
}
