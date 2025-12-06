# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-12-06

### Added
- Context handling system for improved binary analysis workflow
- Conversation history management in agent
- New snapshot fixtures for testing
- Enhanced CLI output handling and user experience
- Comprehensive test coverage for conversation history management

### Changed
- **BREAKING:** Adopted opinionated 4-command CLI architecture (init, snapshot, analyze, chat)
- Major refactor: modular installation system with improved scripts
- Updated Dockerfile for better functionality
- Enhanced message handling in ReverseEngineeringAgent
- Improved CLI banner presentation

### Fixed
- CI release notes now fetch full git history to detect previous tags
- ASCII art logo rendering in CLI banner

### Documentation
- Complete documentation overhaul
- Added license compliance (NOTICE file)
- Updated README with new CLI architecture

### Removed
- Deprecated prompts from prompts.py

## [1.0.3] - 2024-12-XX

### Initial Release
- Core functionality for reverse engineering with Ghidra snapshots
- LLM-powered binary analysis agent
- CAPA integration for capability detection
- Snapshot extraction and management
- Basic CLI interface

[1.1.0]: https://github.com/Karib0u/kernagent/compare/v1.0.3...v1.1.0
[1.0.2]: https://github.com/Karib0u/kernagent/releases/tag/v1.0.2
