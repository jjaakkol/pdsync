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

- Paralel fire removal
- Better scheduling
- Faster directory scan
- Remove some unnecessary complicated code
- Fix hard links
- cp command
- rm command
- find command
- Working sparse files
- In place updating

## License

This project is licensed under the GNU GPLv3. See [LICENSE](LICENSE) for details.

## Author

Jani Jaakkola (<jani.jaakkola@helsinki.fi>)