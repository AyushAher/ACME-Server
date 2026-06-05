rm -rf ./build
cmake -S . -B build
cmake --build build
cp build/acme_server_demo acme_server_demo
./acme_server_demo