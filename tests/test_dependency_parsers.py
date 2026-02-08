"""Tests for dependency parsers (app/services/dependencies.py).

Covers all 9 supported manifest formats:
 - Python: requirements.txt, pyproject.toml
 - Node.js: package.json
 - Java: pom.xml, build.gradle, build.gradle.kts
 - Go: go.mod
 - Rust: Cargo.toml
 - Ruby: Gemfile, *.gemspec

Also tests the top-level extract_dependencies dispatcher,
MANIFEST_FILES constant, and SBOM purl generation for new ecosystems.
"""
import pytest
from typing import List, Dict

from app.services.dependencies import (
    extract_dependencies,
    MANIFEST_FILES,
    _parse_requirements_txt,
    _parse_package_json,
    _parse_pyproject_toml,
    _parse_pom_xml,
    _parse_build_gradle,
    _parse_go_mod,
    _parse_cargo_toml,
    _parse_gemfile,
    _parse_gemspec,
)
from app.services.sbom import _build_purl


# ===========================================================================
# Test fixtures — sample manifest contents
# ===========================================================================

SAMPLE_POM_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>myapp</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>3.2.0</version>
        </dependency>
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>32.1.3-jre</version>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <version>${lombok.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
        </dependency>
    </dependencies>
</project>
"""

SAMPLE_BUILD_GRADLE = """\
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'
    implementation "com.google.guava:guava:32.1.3-jre"
    testImplementation 'junit:junit:4.13.2'
    compileOnly 'org.projectlombok:lombok:1.18.30'
    runtimeOnly 'com.h2database:h2:2.2.224'
    annotationProcessor 'org.projectlombok:lombok:1.18.30'
}
"""

SAMPLE_BUILD_GRADLE_KTS = """\
plugins {
    kotlin("jvm") version "1.9.0"
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    api("com.squareup.okhttp3:okhttp:4.12.0")
}
"""

SAMPLE_GO_MOD = """\
module github.com/example/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/go-sql-driver/mysql v1.7.0 // indirect
\tgolang.org/x/text v0.14.0
)

require github.com/stretchr/testify v1.8.4
"""

SAMPLE_CARGO_TOML = """\
[package]
name = "myapp"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
serde_json = { version = "1.0", features = ["preserve_order"] }
tokio = { version = "1.35", features = ["full"] }
log = "0.4"

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
tempfile = "3.9"

[build-dependencies]
cc = "1.0"
"""

SAMPLE_GEMFILE = """\
source 'https://rubygems.org'

ruby '3.2.0'

gem 'rails', '~> 7.1'
gem 'pg', '>= 1.5'
gem 'puma', '~> 6.0'
gem 'sidekiq'
gem 'redis', '>= 4.0'

group :development, :test do
  gem 'rspec-rails', '~> 6.0'
  gem 'factory_bot_rails'
end

group :production do
  gem 'newrelic_rpm'
end
"""

SAMPLE_GEMSPEC = """\
Gem::Specification.new do |spec|
  spec.name          = "my_gem"
  spec.version       = "1.0.0"
  spec.summary       = "A test gem"

  spec.add_dependency "rake", "~> 13.0"
  spec.add_dependency "rspec", ">= 3.0"
  spec.add_runtime_dependency "concurrent-ruby", "~> 1.2"
  spec.add_development_dependency "rubocop", "~> 1.50"
  spec.add_development_dependency "simplecov"
end
"""


# ===========================================================================
# 1. Maven pom.xml
# ===========================================================================

class TestPomXml:
    def test_basic_parsing(self):
        deps = _parse_pom_xml(SAMPLE_POM_XML)
        assert len(deps) == 4

    def test_group_artifact_format(self):
        deps = _parse_pom_xml(SAMPLE_POM_XML)
        names = [d["name"] for d in deps]
        assert "org.springframework.boot:spring-boot-starter-web" in names
        assert "com.google.guava:guava" in names

    def test_version_extracted(self):
        deps = _parse_pom_xml(SAMPLE_POM_XML)
        spring = next(d for d in deps if "spring-boot" in d["name"])
        assert spring["version"] == "3.2.0"

    def test_property_placeholder_preserved(self):
        deps = _parse_pom_xml(SAMPLE_POM_XML)
        lombok = next(d for d in deps if "lombok" in d["name"])
        assert lombok["version"] == "${lombok.version}"

    def test_missing_version(self):
        deps = _parse_pom_xml(SAMPLE_POM_XML)
        junit = next(d for d in deps if "junit:junit" in d["name"])
        assert junit["version"] == "unspecified"

    def test_extract_dependencies_dispatch(self):
        deps = extract_dependencies("project/pom.xml", SAMPLE_POM_XML)
        assert len(deps) == 4
        assert all(d["type"] == "java" for d in deps)
        assert all(d["file_source"] == "project/pom.xml" for d in deps)

    def test_empty_pom(self):
        deps = _parse_pom_xml("<project></project>")
        assert deps == []

    def test_invalid_xml(self):
        deps = _parse_pom_xml("not xml at all")
        assert deps == []


# ===========================================================================
# 2. Gradle build.gradle / build.gradle.kts
# ===========================================================================

class TestBuildGradle:
    def test_groovy_dsl_parsing(self):
        deps = _parse_build_gradle(SAMPLE_BUILD_GRADLE)
        # 5 unique: lombok appears as compileOnly + annotationProcessor but is deduped
        assert len(deps) == 5

    def test_groovy_configurations(self):
        deps = _parse_build_gradle(SAMPLE_BUILD_GRADLE)
        names = [d["name"] for d in deps]
        assert "org.springframework.boot:spring-boot-starter-web" in names
        assert "junit:junit" in names
        assert "org.projectlombok:lombok" in names
        assert "com.h2database:h2" in names

    def test_groovy_versions(self):
        deps = _parse_build_gradle(SAMPLE_BUILD_GRADLE)
        guava = next(d for d in deps if "guava" in d["name"])
        assert guava["version"] == "32.1.3-jre"

    def test_kotlin_dsl_parsing(self):
        deps = _parse_build_gradle(SAMPLE_BUILD_GRADLE_KTS)
        assert len(deps) == 3
        names = [d["name"] for d in deps]
        assert "org.jetbrains.kotlinx:kotlinx-coroutines-core" in names
        assert "com.squareup.okhttp3:okhttp" in names

    def test_extract_dependencies_gradle(self):
        deps = extract_dependencies("app/build.gradle", SAMPLE_BUILD_GRADLE)
        assert all(d["type"] == "java" for d in deps)

    def test_extract_dependencies_gradle_kts(self):
        deps = extract_dependencies("app/build.gradle.kts", SAMPLE_BUILD_GRADLE_KTS)
        assert all(d["type"] == "java" for d in deps)
        assert len(deps) == 3

    def test_empty_gradle(self):
        deps = _parse_build_gradle("apply plugin: 'java'\n")
        assert deps == []


# ===========================================================================
# 3. Go go.mod
# ===========================================================================

class TestGoMod:
    def test_basic_parsing(self):
        deps = _parse_go_mod(SAMPLE_GO_MOD)
        assert len(deps) == 4

    def test_module_names(self):
        deps = _parse_go_mod(SAMPLE_GO_MOD)
        names = [d["name"] for d in deps]
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/go-sql-driver/mysql" in names
        assert "golang.org/x/text" in names
        assert "github.com/stretchr/testify" in names

    def test_version_without_v_prefix(self):
        deps = _parse_go_mod(SAMPLE_GO_MOD)
        gin = next(d for d in deps if "gin" in d["name"])
        assert gin["version"] == "1.9.1"

    def test_indirect_included(self):
        deps = _parse_go_mod(SAMPLE_GO_MOD)
        mysql = next(d for d in deps if "mysql" in d["name"])
        assert mysql["version"] == "1.7.0"

    def test_single_line_require(self):
        deps = _parse_go_mod(SAMPLE_GO_MOD)
        testify = next(d for d in deps if "testify" in d["name"])
        assert testify["version"] == "1.8.4"

    def test_extract_dependencies_dispatch(self):
        deps = extract_dependencies("go.mod", SAMPLE_GO_MOD)
        assert all(d["type"] == "go" for d in deps)
        assert len(deps) == 4

    def test_empty_go_mod(self):
        deps = _parse_go_mod("module example.com/foo\n\ngo 1.21\n")
        assert deps == []


# ===========================================================================
# 4. Rust Cargo.toml
# ===========================================================================

class TestCargoToml:
    def test_basic_parsing(self):
        deps = _parse_cargo_toml(SAMPLE_CARGO_TOML)
        assert len(deps) == 7

    def test_simple_version(self):
        deps = _parse_cargo_toml(SAMPLE_CARGO_TOML)
        serde = next(d for d in deps if d["name"] == "serde")
        assert serde["version"] == "1.0"

    def test_table_version(self):
        deps = _parse_cargo_toml(SAMPLE_CARGO_TOML)
        tokio = next(d for d in deps if d["name"] == "tokio")
        assert tokio["version"] == "1.35"

    def test_dev_dependencies(self):
        deps = _parse_cargo_toml(SAMPLE_CARGO_TOML)
        names = [d["name"] for d in deps]
        assert "criterion" in names
        assert "tempfile" in names

    def test_build_dependencies(self):
        deps = _parse_cargo_toml(SAMPLE_CARGO_TOML)
        cc = next(d for d in deps if d["name"] == "cc")
        assert cc["version"] == "1.0"

    def test_extract_dependencies_dispatch(self):
        deps = extract_dependencies("Cargo.toml", SAMPLE_CARGO_TOML)
        assert all(d["type"] == "rust" for d in deps)
        assert len(deps) == 7

    def test_empty_cargo(self):
        deps = _parse_cargo_toml("[package]\nname = 'foo'\nversion = '0.1.0'\n")
        assert deps == []

    def test_path_dependency(self):
        content = '[dependencies]\nmylib = { path = "../mylib" }\n'
        deps = _parse_cargo_toml(content)
        assert len(deps) == 1
        assert deps[0]["version"] == "unspecified"


# ===========================================================================
# 5. Ruby Gemfile
# ===========================================================================

class TestGemfile:
    def test_basic_parsing(self):
        deps = _parse_gemfile(SAMPLE_GEMFILE)
        assert len(deps) >= 8

    def test_versioned_gems(self):
        deps = _parse_gemfile(SAMPLE_GEMFILE)
        rails = next(d for d in deps if d["name"] == "rails")
        assert rails["version"] == "~> 7.1"

    def test_unversioned_gem(self):
        deps = _parse_gemfile(SAMPLE_GEMFILE)
        sidekiq = next(d for d in deps if d["name"] == "sidekiq")
        assert sidekiq["version"] == "unspecified"

    def test_group_gems_included(self):
        deps = _parse_gemfile(SAMPLE_GEMFILE)
        names = [d["name"] for d in deps]
        assert "rspec-rails" in names
        assert "newrelic_rpm" in names

    def test_extract_dependencies_dispatch(self):
        deps = extract_dependencies("Gemfile", SAMPLE_GEMFILE)
        assert all(d["type"] == "ruby" for d in deps)
        assert len(deps) >= 8


# ===========================================================================
# 6. Ruby gemspec
# ===========================================================================

class TestGemspec:
    def test_basic_parsing(self):
        deps = _parse_gemspec(SAMPLE_GEMSPEC)
        assert len(deps) == 5

    def test_add_dependency(self):
        deps = _parse_gemspec(SAMPLE_GEMSPEC)
        rake = next(d for d in deps if d["name"] == "rake")
        assert rake["version"] == "~> 13.0"

    def test_runtime_dependency(self):
        deps = _parse_gemspec(SAMPLE_GEMSPEC)
        cr = next(d for d in deps if d["name"] == "concurrent-ruby")
        assert cr["version"] == "~> 1.2"

    def test_dev_dependency(self):
        deps = _parse_gemspec(SAMPLE_GEMSPEC)
        names = [d["name"] for d in deps]
        assert "rubocop" in names

    def test_unversioned_dev_dep(self):
        deps = _parse_gemspec(SAMPLE_GEMSPEC)
        simplecov = next(d for d in deps if d["name"] == "simplecov")
        assert simplecov["version"] == "unspecified"

    def test_extract_dependencies_dispatch(self):
        deps = extract_dependencies("my_gem.gemspec", SAMPLE_GEMSPEC)
        assert all(d["type"] == "ruby" for d in deps)


# ===========================================================================
# 7. MANIFEST_FILES constant
# ===========================================================================

class TestManifestFiles:
    def test_includes_all_ecosystems(self):
        assert "pom.xml" in MANIFEST_FILES
        assert "build.gradle" in MANIFEST_FILES
        assert "build.gradle.kts" in MANIFEST_FILES
        assert "go.mod" in MANIFEST_FILES
        assert "Cargo.toml" in MANIFEST_FILES
        assert "Gemfile" in MANIFEST_FILES

    def test_includes_existing(self):
        assert "requirements.txt" in MANIFEST_FILES
        assert "package.json" in MANIFEST_FILES
        assert "pyproject.toml" in MANIFEST_FILES

    def test_count(self):
        assert len(MANIFEST_FILES) >= 10


# ===========================================================================
# 8. Dispatcher edge cases
# ===========================================================================

class TestExtractDependenciesDispatcher:
    def test_unknown_file(self):
        deps = extract_dependencies("README.md", "# Hello")
        assert deps == []

    def test_case_insensitive_match(self):
        deps = extract_dependencies("project/GO.MOD", SAMPLE_GO_MOD)
        # go.mod basename comparison is lowercased
        assert len(deps) == 4

    def test_nested_path(self):
        deps = extract_dependencies("backend/services/Cargo.toml", SAMPLE_CARGO_TOML)
        assert all(d["file_source"] == "backend/services/Cargo.toml" for d in deps)

    def test_windows_path(self):
        deps = extract_dependencies("C:\\project\\pom.xml", SAMPLE_POM_XML)
        assert len(deps) == 4


# ===========================================================================
# 9. SBOM purl generation for new ecosystems
# ===========================================================================

class TestPurlGeneration:
    def test_java_purl(self):
        purl = _build_purl({"name": "org.springframework:spring-core", "version": "6.1.0", "type": "java"})
        assert purl == "pkg:maven/org.springframework/spring-core@6.1.0"

    def test_java_purl_no_version(self):
        purl = _build_purl({"name": "junit:junit", "version": "unspecified", "type": "java"})
        assert purl == "pkg:maven/junit/junit"

    def test_go_purl(self):
        purl = _build_purl({"name": "github.com/gin-gonic/gin", "version": "1.9.1", "type": "go"})
        assert purl == "pkg:golang/github.com/gin-gonic/gin@1.9.1"

    def test_rust_purl(self):
        purl = _build_purl({"name": "serde", "version": "1.0", "type": "rust"})
        assert purl == "pkg:cargo/serde@1.0"

    def test_ruby_purl(self):
        purl = _build_purl({"name": "rails", "version": "~> 7.1", "type": "ruby"})
        assert purl == "pkg:gem/rails@~> 7.1"

    def test_existing_python_purl(self):
        purl = _build_purl({"name": "requests", "version": "2.31.0", "type": "python"})
        assert purl == "pkg:pypi/requests@2.31.0"

    def test_existing_node_purl(self):
        purl = _build_purl({"name": "express", "version": "4.18.2", "type": "node"})
        assert purl == "pkg:npm/express@4.18.2"

    def test_unspecified_version_no_at(self):
        purl = _build_purl({"name": "tokio", "version": "unspecified", "type": "rust"})
        assert purl == "pkg:cargo/tokio"
        assert "@" not in purl


# ===========================================================================
# 10. Existing parsers still work (regression)
# ===========================================================================

class TestExistingParsersRegression:
    def test_requirements_txt(self):
        content = "requests==2.31.0\nflask>=2.0\nclick\n"
        deps = extract_dependencies("requirements.txt", content)
        assert len(deps) == 3
        assert all(d["type"] == "python" for d in deps)

    def test_package_json(self):
        content = '{"dependencies": {"express": "^4.18.2"}, "devDependencies": {"jest": "^29.0"}}'
        deps = extract_dependencies("package.json", content)
        assert len(deps) == 2
        assert all(d["type"] == "node" for d in deps)

    def test_pyproject_toml(self):
        content = "[tool.poetry.dependencies]\npython = \"^3.11\"\nfastapi = \"^0.100\"\n"
        deps = extract_dependencies("pyproject.toml", content)
        assert len(deps) == 1  # python is skipped
        assert deps[0]["name"] == "fastapi"


# ===========================================================================
# 11. Hardened parser edge cases (tomllib, namespace XML, etc.)
# ===========================================================================

class TestHardenedPyprojectToml:
    """Tests for tomllib-backed pyproject.toml parser."""

    def test_pep621_dependencies(self):
        content = '''
[project]
name = "myapp"
dependencies = [
    "requests>=2.28",
    "click~=8.0",
    "rich",
]
'''
        deps = _parse_pyproject_toml(content)
        names = [d["name"] for d in deps]
        assert "requests" in names
        assert "click" in names
        assert "rich" in names

    def test_pep621_optional_dependencies(self):
        content = '''
[project]
name = "myapp"
[project.optional-dependencies]
dev = ["pytest>=7.0", "black"]
docs = ["sphinx"]
'''
        deps = _parse_pyproject_toml(content)
        assert len(deps) == 3

    def test_pep621_extras_stripped(self):
        content = '''
[project]
dependencies = ["uvicorn[standard]>=0.20"]
'''
        deps = _parse_pyproject_toml(content)
        assert deps[0]["name"] == "uvicorn"

    def test_poetry_inline_table(self):
        content = '''
[tool.poetry.dependencies]
python = "^3.11"
sqlalchemy = {version = "^2.0", extras = ["asyncio"]}
'''
        deps = _parse_pyproject_toml(content)
        assert len(deps) == 1  # python skipped
        assert deps[0]["name"] == "sqlalchemy"
        assert deps[0]["version"] == "^2.0"

    def test_poetry_group_dependencies(self):
        content = '''
[tool.poetry.group.test.dependencies]
pytest = "^7.0"
coverage = {version = "^7.0", extras = ["toml"]}
'''
        deps = _parse_pyproject_toml(content)
        assert len(deps) == 2

    def test_multiline_array(self):
        content = '''
[project]
dependencies = [
    "numpy>=1.24",
    "pandas>=2.0,<3",
]
'''
        deps = _parse_pyproject_toml(content)
        assert len(deps) == 2

    def test_invalid_toml(self):
        deps = _parse_pyproject_toml("this is not valid toml [[[")
        assert deps == []

    def test_environment_markers_stripped(self):
        content = '''
[project]
dependencies = ["pywin32>=300 ; sys_platform == 'win32'"]
'''
        deps = _parse_pyproject_toml(content)
        assert deps[0]["name"] == "pywin32"


class TestHardenedCargoToml:
    """Tests for tomllib-backed Cargo.toml parser."""

    def test_workspace_dependencies(self):
        content = '''
[workspace.dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }
'''
        deps = _parse_cargo_toml(content)
        assert len(deps) == 2

    def test_target_specific_deps(self):
        content = '''
[dependencies]
libc = "0.2"

[target.'cfg(windows)'.dependencies]
winapi = { version = "0.3", features = ["winuser"] }
'''
        deps = _parse_cargo_toml(content)
        names = [d["name"] for d in deps]
        assert "libc" in names
        assert "winapi" in names

    def test_git_dependency_no_version(self):
        content = '''
[dependencies]
my-lib = { git = "https://github.com/me/my-lib.git" }
'''
        deps = _parse_cargo_toml(content)
        assert deps[0]["version"] == "unspecified"

    def test_invalid_toml(self):
        deps = _parse_cargo_toml("not valid [[[")
        assert deps == []


class TestHardenedPomXml:
    """Tests for namespace-aware pom.xml parser."""

    def test_namespaced_pom(self):
        content = '''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.1.0</version>
        </dependency>
    </dependencies>
</project>'''
        deps = _parse_pom_xml(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "org.springframework:spring-core"
        assert deps[0]["version"] == "6.1.0"

    def test_dependency_management_section(self):
        content = '''<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.fasterxml.jackson</groupId>
                <artifactId>jackson-bom</artifactId>
                <version>2.16.0</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
        </dependency>
    </dependencies>
</project>'''
        deps = _parse_pom_xml(content)
        assert len(deps) == 2
        names = [d["name"] for d in deps]
        assert "com.fasterxml.jackson:jackson-bom" in names
        assert "junit:junit" in names


class TestHardenedGradle:
    """Tests for improved Gradle parser."""

    def test_managed_dep_no_version(self):
        content = "dependencies {\n    implementation 'org.slf4j:slf4j-api'\n}\n"
        deps = _parse_build_gradle(content)
        assert len(deps) == 1
        assert deps[0]["version"] == "unspecified"

    def test_platform_deps(self):
        content = """dependencies {
    implementation platform('org.springframework.boot:spring-boot-dependencies:3.2.0')
}"""
        deps = _parse_build_gradle(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "org.springframework.boot:spring-boot-dependencies"
        assert deps[0]["version"] == "3.2.0"

    def test_no_duplicates(self):
        content = """dependencies {
    implementation 'com.google.guava:guava:32.0'
    testImplementation 'com.google.guava:guava:32.0'
}"""
        deps = _parse_build_gradle(content)
        names = [d["name"] for d in deps]
        assert names.count("com.google.guava:guava") == 1

    def test_ksp_configuration(self):
        content = "dependencies {\n    ksp 'com.google.dagger:hilt-compiler:2.48'\n}\n"
        deps = _parse_build_gradle(content)
        assert len(deps) == 1


class TestHardenedRequirementsTxt:
    """Tests for improved requirements.txt parser."""

    def test_extras(self):
        content = "uvicorn[standard]>=0.20\n"
        deps = _parse_requirements_txt(content)
        assert deps[0]["name"] == "uvicorn"

    def test_url_dep(self):
        content = "mypackage @ https://github.com/me/mypackage/archive/main.zip\n"
        deps = _parse_requirements_txt(content)
        assert deps[0]["name"] == "mypackage"
        assert "https://" in deps[0]["version"]

    def test_editable_skipped(self):
        content = "-e ./local-pkg\nrequests==2.31.0\n"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "requests"

    def test_env_markers_stripped(self):
        content = "pywin32>=300 ; sys_platform == 'win32'\n"
        deps = _parse_requirements_txt(content)
        assert deps[0]["name"] == "pywin32"

    def test_line_continuation(self):
        content = "requests\\\n==2.31.0\n"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "requests"

    def test_constraint_flag_skipped(self):
        content = "-c constraints.txt\nflask==2.0\n"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1

    def test_index_url_skipped(self):
        content = "--index-url https://pypi.org/simple\nrequests==2.31.0\n"
        deps = _parse_requirements_txt(content)
        assert len(deps) == 1


class TestHardenedGemfile:
    """Tests for improved Gemfile parser."""

    def test_git_source_skipped(self):
        content = "gem 'my_fork', git: 'https://github.com/me/fork.git'\ngem 'rails', '~> 7.0'\n"
        deps = _parse_gemfile(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "rails"

    def test_path_source_skipped(self):
        content = "gem 'local_gem', path: '../local_gem'\ngem 'puma'\n"
        deps = _parse_gemfile(content)
        assert len(deps) == 1
        assert deps[0]["name"] == "puma"
