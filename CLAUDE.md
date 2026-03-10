# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Lakerfield.Acme is a .NET 10 library for interacting with Acme (Automated Certificate Management Environment). It implements RFC 8555 (ACME protocol specification).

## Architecture

The solution contains two projects:

- **Lakerfield.Acme** (`src/Lakerfield.Acme/`) - The main library project exposing `LakerfieldAcmeClient` class
- **Lakerfield.Acme.Playground** (`src/Lakerfield.Acme.Playground/`) - A console application for testing and experimenting with the library

## Commands

### Build
```bash
dotnet build
```

### Run Playground
```bash
dotnet run --project src/Lakerfield.Acme.Playground
```

### Format Code
```bash
dotnet format
```

### Check Formatting (Pre-commit)
```bash
dotnet format --verify-no-changes
```

## Notes

- The project uses .NET 10 (`TargetFramework>net10.0`)
- Implicit usings are disabled, requiring explicit `using` statements
- Nullable reference types are enabled
- A pre-commit hook enforces code formatting before commits (stored in `.githooks/pre-commit`)
