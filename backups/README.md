应使用docker编译python  
编译python前应该编译安装好openssl、libffi-dev、zlib1g-dev等依赖
建议拉取docker pull ubuntu:16.04编译产出的python兼容性强
docker run -it ubuntu:16.04 /bin/bash
