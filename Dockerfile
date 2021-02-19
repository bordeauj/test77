FROM ubuntu

ENV THEDIR=/77

RUN mkdir $THEDIR

WORKDIR $THEDIR

# Install tools required for project
# Run `docker build --no-cache .` to update dependencies
RUN apt-get update
RUN apt-get install -y wget make gcc libpcre3 libpcre3-dev libssl-dev zlib1g zlib1g-dev libgetopt-complete-perl
# Maybe try also RUN apt-get install -y wget make gcc; apt-get -y build-dep nginx
RUN wget https://openresty.org/download/openresty-1.19.3.1.tar.gz; tar -xzf openresty-1.19.3.1.tar.gz; rm *.tar.gz

WORKDIR openresty-1.19.3.1

COPY ngx_http_upstream.c ./bundle/nginx-1.19.3/src/http/

RUN    ./configure --with-debug; \
    make; \
    make install

# Misc
WORKDIR $THEDIR
# RUN apt-get install -y vim
RUN mkdir logs

# Copy the entire project and build it
# This layer is rebuilt when a file changes in the project directory
ENV PATH="/usr/local/openresty/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/luajit/bin:${PATH}"
ENV LD_LIBRARY_PATH="/77:${LD_LIBRARY_PATH}"
COPY . .

# This results in a single layer image
ENTRYPOINT ["/bin/bash"]
#CMD ["--help"]
