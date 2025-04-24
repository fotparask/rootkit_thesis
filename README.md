# Linux Kernel Module Rootkit Thesis

## Overview

This repository contains the implementation of various Linux Kernel Module (LKM) rootkits developed for academic research as part of my thesis on operating system security. The project demonstrates both basic and advanced rootkit techniques using kernel-level manipulations.

---

## Academic Purpose

This code is developed strictly for educational and research purposes. All testing should be performed in isolated environments.

---

## Features

- **Basic kernel module concealment techniques**
- **Process hiding capabilities**
- **Advanced syscall hooking using ftrace**
- **Persistence mechanisms**

---

## Implementation Details

### Basic Modules

The repository includes fundamental LKM rootkits:

- Hello world functionality

### Advanced Techniques

More sophisticated implementations leverage `ftrace` for syscall hooking, providing:

- Lower detection footprint
- Compatibility with modern kernels (5.x and 6.x)
- More reliable operation across kernel versions


---

## Compatibility

Tested on Linux kernel versions **5.x** and **6.x** on **x86_64** architecture.

---

## Thesis Context

This implementation serves as the practical component of research examining kernel-level security mechanisms, detection techniques, and defensive countermeasures.

---

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.


