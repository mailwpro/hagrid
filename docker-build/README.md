# Instructions

This docker image can be used to build hagrid for a Debian environment.

```sh
# in the main source directory
docker build -t hagrid-builder:1.0 docker-build/
# bind in volumes to use cache from hosts
docker run --rm -i -t --user $UID --volume $PWD:/home/user/src --volume $HOME/.cargo/registry:/usr/local/cargo/registry --volume $HOME/.cargo/git:/usr/local/cargo/git hagrid-builder:1.0 cargo build --release --frozen
# release artifact will be in target directory
```
