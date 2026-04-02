# PowerShell Attack Pattern Levels

This file defines the staged known-pattern coverage in the current pipeline.

## Level 1

Broad suspicious primitives and wrappers:

- encoded execution
- hidden / bypass execution wrappers
- `Invoke-Expression`
- download primitives
- AD / host reconnaissance

## Level 2

Known attack chains and persistence mechanisms:

- download and execute chains
- compression / layered loaders
- reflection or dynamic assembly loading
- direct `System.Management.Automation` abuse
- run key persistence
- scheduled task persistence
- service persistence
- PowerShell remoting / WinRM lateral movement

## Level 3

High-severity behaviors that often deserve immediate analyst review:

- AMSI bypass references
- WMI event subscription persistence
- shadow copy destruction
- in-memory loader / shellcode interop primitives

## Why Levels Exist

The system does not attempt to model every possible PowerShell attack variant at once.
Instead it builds coverage in stages:

1. cover major known families
2. review misses and disagreements
3. add new rules or new labels
4. retrain stronger models

## Current Scope Limits

Current rule coverage is strongest for:

- execution wrappers
- download cradles
- obfuscation
- persistence
- AMSI / reflection references
- remote execution primitives

Current rule coverage is weaker for:

- very low-signal bespoke malware
- environment-specific admin tooling that resembles offensive tradecraft
- advanced semantic evasion that requires full AST or runtime context

