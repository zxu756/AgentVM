==> [readme-commands] Checking README.md & README.zh-CN.md for banned claims...
PASS: Zero banned claims in README.md and README.zh-CN.md
PASS: README.md and README.zh-CN.md list the same 34 commands
==> [readme-commands] Replaying README.md
SKIP (this script already built the product above): swift build --product AgentVM
SKIP (the replay substitutes the built binary for `agentvm`): alias agentvm="$(pwd)/.build/debug/AgentVM"
SKIP (test entry point; running it from here would recurse): ./Scripts/test.sh scope AgentVMStore AgentVMHypervisor AgentVMCLIAndMCP
SKIP (this script itself): ./Scripts/acceptance/readme-commands.sh
SKIP (test entry point; running it from here would recurse): ./Scripts/test.sh milestone 0
SKIP (real-VM acceptance entry point; it boots guests and downloads an image, so the README replay never runs it): AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 1
SKIP (real-VM acceptance entry point; it boots guests and downloads an image, so the README replay never runs it): AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 2
SKIP (real-VM acceptance entry point; it boots guests and downloads an image, so the README replay never runs it): AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 3
SKIP (packaging step, builds the release .app bundle): ./Scripts/build-app.sh
SKIP (launches the desktop UI; no script may do that): open build/AgentVM.app
SKIP (launches the desktop UI; no script may do that): ./build/AgentVM.app/Contents/MacOS/AgentVM --demo
PASS: README.md: replayed 23 agentvm commands, checked 22 documented outputs, skipped 11 non-replayable lines
==> [readme-commands] Replaying README.zh-CN.md
SKIP (this script already built the product above): swift build --product AgentVM
SKIP (the replay substitutes the built binary for `agentvm`): alias agentvm="$(pwd)/.build/debug/AgentVM"
SKIP (test entry point; running it from here would recurse): ./Scripts/test.sh scope AgentVMStore AgentVMHypervisor AgentVMCLIAndMCP
SKIP (this script itself): ./Scripts/acceptance/readme-commands.sh
SKIP (test entry point; running it from here would recurse): ./Scripts/test.sh milestone 0
SKIP (real-VM acceptance entry point; it boots guests and downloads an image, so the README replay never runs it): AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 1
SKIP (real-VM acceptance entry point; it boots guests and downloads an image, so the README replay never runs it): AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 2
SKIP (real-VM acceptance entry point; it boots guests and downloads an image, so the README replay never runs it): AGENTVM_REAL_VM=1 ./Scripts/test.sh milestone 3
SKIP (packaging step, builds the release .app bundle): ./Scripts/build-app.sh
SKIP (launches the desktop UI; no script may do that): open build/AgentVM.app
SKIP (launches the desktop UI; no script may do that): ./build/AgentVM.app/Contents/MacOS/AgentVM --demo
PASS: README.zh-CN.md: replayed 23 agentvm commands, checked 22 documented outputs, skipped 11 non-replayable lines
ALL README COMMAND CHECKS PASSED.
