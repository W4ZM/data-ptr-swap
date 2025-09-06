# data-ptr-swap

A Windows kernel driver that hooks the `NtUserCreateWindowStation` function in `win32k.sys` by swapping its pointer to your function in your mapped driver.

---

## Features

- Mapped with [Kdmapper](https://github.com/TheCruZ/kdmapper). 
- IoCreateDriver (from [Th3Spl](https://github.com/Th3Spl/IoCreateDriver)).  
- Uses shared memory (section objects) communication.  
- Uses physical memory to read/write process virtual memory.

## Requirements

- Cmake.
- Windows 11 (24H2).
- Visual Studio.
- [wdk](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).

## How to build

```bash
git clone https://github.com/W4ZM/data-ptr-swap.git
cd data-ptr-swap && mkdir build && cd build
cmake ..
cmake --build . --config release
```
---

*Credits to [FindWdk](https://github.com/SergiusTheBest/FindWDK) for making it easier to build Windows drivers with CMake.*
