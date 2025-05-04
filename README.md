# BastionEDR

BastionEDR is purely a learning project that has 2 components: BastionEDRAgent and BastionEdrDLL.
The BastionEDRAgent is the Agent that will monitor the system and will inject the BastionEdrDLL in the memory of processes.
It will skip services ( to avoid any issues ) and it will only filter some processes for now.

## BastionEdrDLL

The injected DLL will search for specific informations such as : PID, Process Environment Block (PEB), etc.
The most important part here is the PEB. The DLL will search for libraries and functions from the Import Table of the Process and will replace the functions with 
the its wrappers of those functions. The wrappers will first collect informations about the functions.
`Examples: my_WriteFile is a wrapper for WriteFile. The wrapper will scan the buffer that was supposed to be written.`

`Example: If the process attempts to run a sequence call such as VirtualAlloc|WriteMemory|VirtualProtect|CreateRemoteThread the process might get killed`
The last example is not optimal, but it is a POC.

## TODOS

1. Make the Agent communicate with the DLLs. At the moment the DLls are the ones killing the processes.
2. Create more POCs and heuristics.
3. Make a better Data Structure.
4. Maybe a GUI?

