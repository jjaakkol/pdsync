# Parallel Directory Sync Tool

A high-performance, multi-threaded tool for synchronizing local directories.

## Features

- Parallel directory traversal and file copying
- Preserves file metadata (permissions, timestamps, etc.)
- Efficient job queue and thread management
- Supports hard links, symlinks, and special files
- Progress reporting

## Usage

```sh
pdsync [options] <source_dir> <target_dir>
```

See `--help` for all options.

## Build

```sh
make
```

## TODO

- Parallel file removal
- Improved scheduling
- Faster directory scanning
- Simplify unnecessarily complicated code
- Fix hard link support
- Implement `cp` command
- Implement `rm` command
- Implement `find` command
- Proper sparse file handling
- In-place file updating

## License

This project is licensed under the GNU GPLv3. See [LICENSE](LICENSE) for details.

## Author

Jani Jaakkola (<jani.jaakkola@helsinki.fi>)