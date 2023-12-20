#!/bin/bash

# 接收命令行参数
number=$1
# 判断$number是否是数字
isdigit=`awk 'BEGIN { if (match(ARGV[1],"^[0-9]+$") != 0) print "true"; else print "false" }' $number`

cmd_result=$(command)

root_crt_name="root"
root_private_key_name="root_private"
root_public_key_name="root_public"

server_crt_name="server"
server_private_key_name="server_private"
server_public_key_name="server_public"

client_crt_name="client"
client_private_key_name="client_private"
client_public_key_name="client_public"

function main()
{

    # 检查参数是否是数字
    if [[ $isdigit == "true" ]]; then
        echo "输入的证书有效期为$number天,正在生成中..."
    else
        echo "请输入合法的证书有效期作为参数!"
        return
    fi

    # 检查目录
    if [ -d "certs" ] 
    then 
        rm -rf certs/*
    else
        mkdir certs
    fi    
    cd certs

    # 1.生成自签名证书
    echo "生成自签名证书"
    echo "生成私钥"
    openssl genpkey -algorithm RSA -out $root_private_key_name.key
    echo "基于私钥创建签名请求"
    openssl req -new -key $root_private_key_name.key -out $root_crt_name.csr -subj "/C=CN/ST=shanghai/L=root/O=SAKURA/OU=it/CN=root.com"
    echo "使用私钥签署自己的证书签名请求,生成自签名证书"
    openssl x509 -req -in $root_crt_name.csr -out $root_crt_name.crt -signkey $root_private_key_name.key -days $number
    echo "保存根证书公钥"
    openssl x509 -pubkey -noout -in $root_crt_name.crt > $root_public_key_name.key
    echo "生成成功,证书有效期为$number天"
    echo ""
    ls

    # 2.生成私有CA签发的证书($server_crt_name)
    echo "生成私有CA签发的证书($server_crt_name)"
    echo "生成server私钥"
    openssl genpkey -algorithm RSA -out $server_private_key_name.key
    echo "基于私钥创建签名请求"
    openssl req -new -key $server_private_key_name.key -out $server_crt_name.csr -subj "/C=CN/ST=hubei/L=server/O=SAKURA/OU=it/CN=server.com"
    echo "使用私钥签署client的证书签名请求,生成自签名证书"
    openssl x509 -req -in $server_crt_name.csr -CA $root_crt_name.crt -CAkey $root_private_key_name.key -CAcreateserial -out $server_crt_name.crt -days $number
    echo "保存server证书公钥"
    openssl x509 -pubkey -noout -in $server_crt_name.crt > $server_public_key_name.key
    echo "生成成功,证书有效期为$number天"
    echo ""

    # 3.生成私有CA签发的证书($client_crt_name)
    echo "生成私有CA签发的证书($client_crt_name)"
    echo "生成client私钥"
    openssl genpkey -algorithm RSA -out $client_private_key_name.key
    echo "基于私钥创建签名请求"
    openssl req -new -key $client_private_key_name.key -out $client_crt_name.csr -subj "/C=CN/ST=shannxi/L=client/O=SAKURA/OU=it/CN=client.com"
    echo "使用私钥签署client的证书签名请求,生成自签名证书"
    openssl x509 -req -in $client_crt_name.csr -CA $root_crt_name.crt -CAkey $root_private_key_name.key -CAcreateserial -out $client_crt_name.crt -days $number
    echo "保存client证书公钥"
    openssl x509 -pubkey -noout -in $client_crt_name.crt > $client_public_key_name.key
    echo "生成成功,证书有效期为$number天"
    echo ""

    # 获取哈希值&文件归类
    cmd_result=`openssl x509 -hash -noout -in $root_crt_name.crt`
    echo "$root_crt_name hash value: $cmd_result"
    ln -s $root_crt_name.crt $cmd_result.0
    mkdir $root_crt_name
    mv $cmd_result.0 $root_crt_name
    mv $root_private_key_name.key $root_crt_name
    mv $root_crt_name* $root_crt_name

    cmd_result=`openssl x509 -hash -noout -in $server_crt_name.crt`
    echo "$server_crt_name hash value: $cmd_result"
    ln -s $server_crt_name.crt $cmd_result.0
    mkdir $server_crt_name
    mv $cmd_result.0 $server_crt_name
    mv $server_private_key_name.key $server_crt_name
    mv $server_crt_name* $server_crt_name

    cmd_result=`openssl x509 -hash -noout -in $client_crt_name.crt`
    echo "$client_crt_name hash value: $cmd_result"
    ln -s $client_crt_name.crt $cmd_result.0
    mkdir $client_crt_name
    mv $cmd_result.0 $client_crt_name
    mv $client_private_key_name.key $client_crt_name
    mv $client_crt_name* $client_crt_name

    echo "证书生成完毕!"
    cd ..
    tree certs
}


# main函数
main