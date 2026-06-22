rm -rf ./build
cmake -S . -B build
cmake --build build
cp build/acme_server_demo acme_server_demo
# ./acme_server_demo
# scp ./acme_server_demo ayush@192.168.1.43:~/acme-server/