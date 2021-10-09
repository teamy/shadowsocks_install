#!/usr/bin/env bash
# shellcheck source=/dev/null

NOW_PID=$$
HOME_DIR=/etc/ssmanager
export PATH=${PATH}:${HOME_DIR}/usr/bin:${HOME_DIR}/usr/sbin:${PWD}

Encryption_method_list=(
	plain
	none
	aes-128-gcm
	aes-256-gcm
	chacha20-ietf-poly1305
)

Generate_random_numbers() (
	min=$1
	max=$(($2 - min + 1))
	num=$((RANDOM + 1000000000)) #增加一个10位的数再求余
	printf '%d' $((num % max + min))
)

Introduction_bar() (
	while IFS= read -r c; do
		printf "\e[1;33m#\e[0m"
	done <<EOF
$(fold -w1)
EOF
	echo
)

Introduction() (
	cat >&1 <<-EOF

		$(printf '%s' "$*" | Introduction_bar)
		$1
		$(printf '%s' "$*" | Introduction_bar)

	EOF
)

Prompt_bar() (
	while IFS= read -r c; do
		printf "\e[1;32m-\e[0m"
	done <<EOF
$(fold -w1)
EOF
	echo
)

Prompt() (
	cat >&1 <<-EOF

		$(printf '%s' "$*" | Prompt_bar)
		$1
		$(printf '%s' "$*" | Prompt_bar)

	EOF
)

# 判断命令是否存在
command_exists() {
	#type -P $@
	command -v "$@" >/dev/null 2>&1
}

#https://stackoverflow.com/a/808740
is_number() {
	[ -n "$1" ] && [ "$1" -eq "$1" ] 2>/dev/null
}

# 按任意键继续
Press_any_key_to_continue() {
	if [ "${Language:=zh-CN}" = "en-US" ]; then
		read -n 1 -r -s -p $'Press any key to start...or Press Ctrl+C to cancel'
	else
		read -n 1 -r -s -p $'请按任意键继续或 Ctrl + C 退出\n'
	fi
}

Curl_get_files() {
	if ! curl -L -s -q --retry 5 --retry-delay 10 --retry-max-time 60 --output "$1" "$2"; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Download $1 failed."
		else
			Prompt "下载 $1 文件时失败！"
		fi
		rm -f "$1"
		Exit
	fi
}

Wget_get_files() {
	if ! wget --no-check-certificate -q -c -t2 -T8 -O "$1" "$2"; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Download $1 failed."
		else
			Prompt "下载 $1 文件时失败！"
		fi
		rm -f "$1"
		Exit
	fi
}

downloader() {
	${python:=python3} <<-EOF
		import os.path
		import sys
		from concurrent.futures import as_completed, ThreadPoolExecutor
		import signal
		from functools import partial
		from threading import Event
		from typing import Iterable
		from urllib.request import urlopen

		from rich.progress import (
		    BarColumn,
		    DownloadColumn,
		    Progress,
		    TaskID,
		    TextColumn,
		    TimeRemainingColumn,
		    TransferSpeedColumn,
		)

		progress = Progress(
		    TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
		    BarColumn(bar_width=None),
		    "[progress.percentage]{task.percentage:>3.1f}%",
		    "•",
		    DownloadColumn(),
		    "•",
		    TransferSpeedColumn(),
		    "•",
		    TimeRemainingColumn(),
		)

		done_event = Event()


		def handle_sigint(signum, frame):
		    done_event.set()


		signal.signal(signal.SIGINT, handle_sigint)


		def copy_url(task_id: TaskID, url: str, path: str) -> None:
		    """Copy data from a url to a local file."""
		    progress.console.log(f"Requesting {url}")
		    response = urlopen(url)
		    # This will break if the response doesn't contain content length
		    progress.update(task_id, total=int(response.info()["Content-length"]))
		    with open(path, "wb") as dest_file:
		        progress.start_task(task_id)
		        for data in iter(partial(response.read, 32768), b""):
		            dest_file.write(data)
		            progress.update(task_id, advance=len(data))
		            if done_event.is_set():
		                return
		    progress.console.log(f"Downloaded {path}")


		def download(urls: str):
		    """Download multuple files to the given directory."""

		    with progress:
		        with ThreadPoolExecutor(max_workers=4) as pool:
		            for url in urls.split(' '):
		                url, dest_path = url.split('+')
		                filename = dest_path.split("/")[-1]
		                task_id = progress.add_task("download",
		                                            filename=filename,
		                                            start=False)
		                pool.submit(copy_url, task_id, url, dest_path)
		download("$@")
	EOF
}

Url_encode_pipe() {
	local LANG=C
	local c
	while IFS= read -r c; do
		case $c in [a-zA-Z0-9.~_-])
			printf '%s' "$c"
			continue
			;;
		esac
		printf '%s' "$c" | od -An -tx1 | tr ' ' % | tr -d '\n'
	done <<EOF
$(fold -w1)
EOF
}

Url_encode() (
	printf '%s' "$*" | Url_encode_pipe
)

#https://stackoverflow.com/questions/238073/how-to-add-a-progress-bar-to-a-shell-script
Progress_Bar() {
	_progress=$((100 * $1 / $2))
	_done=$((_progress * 4 / 10))
	_left=$((40 - _done))

	_fill=$(printf "%${_done}s")
	_empty=$(printf "%${_left}s")

	local run
	if [ "$3" ]; then
		[ ${#3} -gt 20 ] && run="${3:0:20}..." || run=$3
	else
		run='Progress'
	fi

	printf "\r${run} : [${_fill// /▇}${_empty// /-}] ${_progress}%%"
	[ ${_progress:-100} -eq 100 ] && echo
}

Address_lookup() {
	unset -v addr
	local cur_time last_time tb_addr
	if [ ! -s /tmp/myaddr ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' https://ipapi.co/json | jq -r '.city + ", " +.region + ", " + .country_name')
		else
			addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' https://myip.ipip.net)
			if [ "$addr" ]; then
				addr=${addr##*\来\自\于}
				addr=${addr:1}
				if [[ $addr == *"台湾"* ]]; then
					addr=${addr/中国/中华民国}
					addr=${addr/台湾省/台湾}
				fi
			else
				#https://wangshengxian.com/article/details/article_id/37.html
				tb_addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' "https://ip.taobao.com/outGetIpInfo?ip=${ipv4:-$ipv6}&accessKey=alibaba-inc")
				if [ "$tb_addr" ]; then
					case $(echo "$tb_addr" | jq -r '.code') in
					0)
						if [ "$(echo "$tb_addr" | jq -r '.data.region')" = "台湾" ]; then
							tb_addr=${tb_addr/中国/中华民国}
							tb_addr=${tb_addr/CN/TW}
						fi
						addr=$(echo "$tb_addr" | jq -r '.data.country + " " +.data.region + " " + .data.country_id')
						;;
					1)
						Prompt "服务器异常"
						;;
					2)
						Prompt "请求参数异常"
						;;
					3)
						Prompt "服务器繁忙"
						;;
					4)
						Prompt "个人qps超出"
						;;
					esac
				fi
			fi
		fi
		[ "$addr" ] && echo "$addr" >/tmp/myaddr
	else
		addr=$(</tmp/myaddr)
		cur_time=$(date +%s)
		last_time=$(date -r /tmp/myaddr +%s)
		#一天后删除重新获取地址
		if [ $((cur_time - last_time)) -gt 86400 ]; then
			rm -f /tmp/myaddr
		fi
	fi
	if [ -z "$addr" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Failed to get attribution location!"
		else
			Prompt "获取归属地位置失败！"
		fi
		Exit
	fi

}

Parsing_User() {
	unset -v server_port password method plugin plugin_opts total
	IFS='|'
	for l in $1; do
		case ${l%^*} in
		server_port)
			server_port=${l#*^}
			;;
		password)
			password=${l#*^}
			;;
		method)
			method=${l#*^}
			;;
		plugin)
			plugin=${l#*^}
			;;
		plugin_opts)
			plugin_opts=${l#*^}
			;;
		total)
			total=${l#*^}
			;;
		esac
	done
}

Parsing_plugin_opts() (
	if [ "$1" ] && [ "$2" ]; then
		IFS=';'
		for l in $1; do
			if [ "${l%=*}" = "$2" ]; then
				printf '%s' "${l#*=}"
			fi
		done
	fi
)

function traffic() {
	${python:=python3} <<-EOF
		def traffic(data: int = 0):
		    if data < 1024:
		        return str(data) + ' Bytes'
		    elif data < 1024**2:
		        return ('%.2f' % (data / 1024) + ' KB')
		    elif data < 1024**3:
		        return ('%.2f' % (data / 1024**2) + ' MB')
		    elif data < 1024**4:
		        return ('%.2f' % (data / 1024**3) + ' GB')
		    elif data < 1024**5:
		        return ('%.2f' % (data / 1024**4) + ' TB')
		    elif data < 1024**6:
		        return ('%.2f' % (data / 1024**5) + ' PB')
		    elif data < 1024**7:
		        return ('%.2f' % (data / 1024**6) + ' EB')
		    elif data < 1024**8:
		        return ('%.2f' % (data / 1024**7) + ' ZB')
		    elif data < 1024**9:
		        return ('%.2f' % (data / 1024**8) + ' YB')
		print(traffic(int($1)))
	EOF
}

Used_traffic() (
	a=$(ss-tool /tmp/ss-manager.socket ping 2>/dev/null)
	b=${a##*\{}
	c=${b%%\}*}
	IFS=','
	for i in ${c//\"/}; do
		IFS=' '
		for j in $i; do
			if [ "${j%\:*}" = "$1" ]; then
				is_number "${j#*\:}" && printf '%d' "${j#*\:}"
			fi
		done
	done
)

Create_certificate() {
	unset -v ca_type eab_kid eab_hmac_key tls_common_name tls_key tls_cert
	tls_key="$HOME_DIR"/ssl/server.key
	tls_cert="$HOME_DIR"/ssl/server.cer
	until [ -s $tls_key ] || [ -s $tls_cert ]; do
		if [ -z "$nginx_on" ] && netstat -ln | grep 'LISTEN' | grep -q ':80 '; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Prompt "Network port 80 is occupied by other processes!"
			else
				Prompt "80端口被其它进程占用！"
			fi
			Exit
		fi
		echo
		if [ -x "${HOME:?}"/.acme.sh/acme.sh ]; then
			"${HOME:?}"/.acme.sh/acme.sh --upgrade
		else
			wget --no-check-certificate -O - https://get.acme.sh | sh
		fi
		while true; do
			cat <<EOF
1. Let’s Encrypt (推荐/Recommend)
2. ZeroSSL
EOF
			read -rp $'请选择/Please select \e[95m1-2\e[0m: ' -n1 action
			case $action in
			1)
				ca_type='letsencrypt'
				break
				;;
			2)
				ca_type='zerossl'
				break
				;;
			esac
		done
		if [ "$ca_type" = "zerossl" ]; then
			Introduction "https://github.com/acmesh-official/acme.sh/wiki/ZeroSSL.com-CA"
			until [ "$eab_kid" ] && [ "$eab_hmac_key" ]; do
				read -rp "EAB KID: " eab_kid
				read -rp "EAB HMAC Key: " eab_hmac_key
			done
			"${HOME:?}"/.acme.sh/acme.sh --register-account --server "$ca_type" --eab-kid "$eab_kid" --eab-hmac-key "$eab_hmac_key"
		fi
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Please enter your domain name to apply for a certificate"
		else
			Introduction "请输入域名以申请证书"

		fi
		until [ "$tls_common_name" ]; do
			read -rp "(${mr:=默认}: example.com): " tls_common_name
			if ! echo "$tls_common_name" | grep -qoE '^([a-zA-Z0-9](([a-zA-Z0-9-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'; then
				unset -v tls_common_name
			fi
		done

		if "${HOME:?}"/.acme.sh/acme.sh --issue --domain "$tls_common_name" "${nginx_on:=--standalone}" -k ec-256 --server "$ca_type" --force; then
			if "${HOME:?}"/.acme.sh/acme.sh --install-cert --domain "$tls_common_name" --cert-file "$tls_cert" --key-file "$tls_key" --ca-file ${HOME_DIR:?}/ssl/ca.cer --fullchain-file ${HOME_DIR:?}/ssl/fullchain.cer --ecc --server "$ca_type" --force; then
				Prompt "$tls_common_name"
			else
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Prompt "Failed to install certificate!"
				else
					Prompt "安装证书失败！"
				fi
				Exit
			fi
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Prompt "Failed to issue certificate!"
			else
				Prompt "签发证书失败!"
			fi
			Exit
		fi

	done
	if [ ! -s $tls_key ] || [ ! -s $tls_cert ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "The certificate file could not be found!"
		else
			Prompt "无法找到证书文件! "
		fi
		Exit
	fi
	tls_common_name=$(openssl x509 -noout -subject -in $tls_cert | cut -d' ' -f3)
	[ -z "$tls_common_name" ] && Exit
}

Check_permissions() (
	for i in $HOME_DIR/port.list $HOME_DIR/ssl/server.cer $HOME_DIR/conf/config.ini; do
		if [ -f $i ]; then
			if [ -f $HOME_DIR/web/subscriptions.php ]; then
				[ "$(stat -c "%U:%G" $i)" != "nobody:root" ] && chown nobody $i
			else
				[ "$(stat -c "%U:%G" $i)" != "root:root" ] && chown root $i
			fi
		fi
	done
)

Local_IP() {
	source ${HOME_DIR:?}/conf/config.ini
	local cs=5
	while true; do
		((cs--))
		if [ ${cs:-0} -eq 0 ]; then
			if [ ${Language:=en-US} = 'zh-CN' ]; then
				Prompt "获取IP地址失败！"
			else
				Prompt "Failed to get IP address!"
			fi
			Exit
		else
			ipv4=$(ip -4 -o route get to 8.8.8.8 2>/dev/null | sed -n 's/.*src \([0-9.]\+\).*/\1/p')
			ipv6=$(ip -6 -o route get to 2001:4860:4860::8888 2>/dev/null | sed -n 's/.*src \([^ ]*\).*/\1/p')
			[ "$ipv4" ] && [ "$Protocol" = "ipv4" ] && unset -v ipv6
			[ -z "$ipv4" ] && [ "$Protocol" = "ipv4" ] && Protocol=auto
			[ "$ipv6" ] && [ "$Protocol" = "ipv6" ] && unset -v ipv4
			[ -z "$ipv6" ] && [ "$Protocol" = "ipv6" ] && Protocol=auto
			[ "$ipv4" ] && [ "$Protocol" = "auto" ] || [ "$ipv6" = "::1" ] && unset -v ipv6
			[ "$ipv4" ] || [ "$ipv6" ] && break
			sleep 1
		fi
	done
	${python:=python3} <<-EOF
		from ipaddress import ip_address
		from subprocess import run
		if not ip_address("${ipv4:-$ipv6}").is_global:
		  if "${Language:=en-US}" == 'zh-CN':
		    print('\n从本机获取到的IP \033[1;41m ${ipv4:-$ipv6} \033[0m 不是公网地址')
		  else:
		    print('\nThe IP \033[1;41m ${ipv4:-$ipv6} \033[0m obtained from this machine is not a public address!')
		  run("kill $NOW_PID", shell=True, check=True, capture_output=True, timeout=2,universal_newlines=True)
	EOF
}

Check() {
	if [ ${UID:=65534} -ne 0 ]; then
		Prompt "You must run this script as root!"
		Exit
	fi
	if command_exists apt; then
		common_install='apt-get -qq install -y --no-install-recommends'
		#common_remove='apt-get purge -y --auto-remove'
	else
		Prompt "The script does not support the package manager in this operating system."
		Exit
	fi
	#https://qastack.cn/ubuntu/481/how-do-i-find-the-package-that-provides-a-file
	local az=0 coi py package_list sorted_arr
	declare -a package_list=(systemctl wget curl netstat pkill socat jq openssl shasum iptables ipset git python3 pip3 ping)
	for i in "${package_list[@]}"; do
		if ! command_exists "$i"; then
			sorted_arr+=("$i")
		fi
	done
	if [ "${#sorted_arr[*]}" -ge 1 ]; then
		#https://brettterpstra.com/2015/03/17/shell-tricks-sort-a-bash-array-by-length/ 重新排列数组
		IFS=$'\n' GLOBIGNORE='*' mapfile -t sorted_arr < <(printf '%s\n' "${sorted_arr[@]}" | awk '{ print length($0) " " $0; }' | sort -n | cut -d ' ' -f 2-)
		for i in "${sorted_arr[@]}"; do
			((az++))
			[ "$az" -le 1 ] && clear
			case $i in
			netstat)
				coi="$common_install net-tools"
				;;
			pkill)
				coi="$common_install psmisc"
				;;
			shasum)
				coi="$common_install libdigest-sha-perl"
				;;
			pip3)
				coi="$common_install python3-pip"
				;;
			systemctl)
				coi="$common_install systemd"
				;;
			ping)
				coi="$common_install iputils-ping"
				;;
			*)
				coi="$common_install $i"
				;;
			esac
			#echo $(((az * 100 / ${#package_list2[*]} * 100) / 100)) | whiptail --gauge "Please wait while installing" 6 60 0
			Progress_Bar "$az" ${#sorted_arr[*]} "Installing $i"
			if ! $coi 1>/dev/null; then
				Prompt "There is an exception when installing the program!"
				Exit
			fi
			#[ $az -eq ${#package_list2[*]} ] && clear
		done
	fi
	if command_exists python3; then
		py=$(python3 -c "import platform
ver = platform.python_version_tuple()
if int(ver[0]) < 3 or int(ver[0]) == 3 and int(ver[1]) < 6:
  print(0)
else:
  print(1)
")
	fi
	if [ "${py:-0}" -eq 0 ]; then
		python="${HOME_DIR}/usr/bin/python3"
		pip="${HOME_DIR}/usr/bin/pip3"
	fi
	if [ ! -d $HOME_DIR ]; then
		mkdir -p $HOME_DIR || Exit
	fi
	for i in conf usr ssl web; do
		if [ ! -d $HOME_DIR/$i ]; then
			mkdir -p $HOME_DIR/$i || Exit
		fi
	done
	for i in bin conf etc html lib php sbin fastcgi_temp client_body_temp; do
		if [ ! -d $HOME_DIR/usr/$i ]; then
			mkdir -p $HOME_DIR/usr/$i || Exit
		fi
	done
	if [ -s $HOME_DIR/conf/config.ini ]; then
		source ${HOME_DIR:?}/conf/config.ini
	fi
	if [ -z "$URL" ]; then
		local test1 test2
		Prompt "Network environment being tested..."
		if [[ "$(ping -c1 -W1 -q -n raw.githubusercontent.com | grep -oE '([0-9]+\.){3}[0-9]+?')" != +(127.0.0.1|0.0.0.0) ]]; then
			test1=0
		else
			test1=1
		fi
		if [ "$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --resolve raw.githubusercontent.com:443:185.199.109.133 https://raw.githubusercontent.com/yiguihai/shadowsocks_install/dev/README.md)" = 200 ]; then
			test2=0
		else
			test2=1
		fi
		#搜索github CDN加速 https://segmentfault.com/a/1190000038298623
		if [ $((test1 + test2)) -eq 0 ]; then
			URL="https://github.com/yiguihai/shadowsocks_install/raw/dev"
		else
			URL="https://cdn.jsdelivr.net/gh/yiguihai/shadowsocks_install@dev"
		fi
	fi
	if [ ! -s $HOME_DIR/conf/config.ini ]; then
		Wget_get_files $HOME_DIR/conf/config.ini $URL/conf/config.ini
		if [ "$URL" ]; then
			echo -e "\nURL=$URL" >>$HOME_DIR/conf/config.ini
		else
			Prompt "Unable to get download node!"
			Exit
		fi
	fi
	if [ "$python" ] && [ "$pip" ]; then
		if [ ! -f ${python:=python3} ] || [ ! -x ${python:=python3} ]; then
			Prompt "Python installation package is being downloaded ..."
			Wget_get_files $HOME_DIR/usr/python.tar.gz https://proxy.freecdn.workers.dev/?url=https://github.com/yiguihai/shadowsocks_install/releases/download/python/python-3.10.0.tar.gz
			Prompt "Unpacking the Python installation package ..."
			tar zxf $HOME_DIR/usr/python.tar.gz -C $HOME_DIR/usr
			rm -f $HOME_DIR/usr/python.tar.gz
			if ${python:=python3} -V; then
				${python:=python3} -m pip install --upgrade pip
			else
				Exit
			fi
		fi
	fi
	Local_IP
	if ! ${python:=python3} -c "import rich" 2>/dev/null; then
		if ! ${pip:=pip3} install -q rich; then
			Prompt "Unable to install rich module!"
			Exit
		fi
	fi
	if [ ! -s $HOME_DIR/conf/update.log ]; then
		Wget_get_files $HOME_DIR/conf/update.log $URL/version/update
	fi
	local dl=() Binary_file_list=("${HOME_DIR:?}/usr/bin/kcptun.sh")
	while IFS= read -r line || [ -n "$line" ]; do
		Binary_file_list+=("${line##* }")
	done <"${HOME_DIR:?}"/conf/update.log
	for x in "${Binary_file_list[@]}"; do
		if [ ! -f "$x" ] || [ ! -x "$x" ]; then
			dl+=("$URL/usr/bin/${x##*/}+$x")
		fi
	done
	if [ "${#dl[@]}" -gt 0 ]; then
		downloader "${dl[@]}"
	fi
	for x in "${Binary_file_list[@]}"; do
		if [ ! -f "$x" ]; then
			Prompt "File $x Download failed!"
			Exit
		fi
		if [ ! -x "$x" ]; then
			chmod +x "$x"
		fi
		if [ "${x##*/}" = "ss-main" ] && [ ! -L /usr/local/bin/"${x##*/}" ]; then
			rm -f /usr/local/bin/"${x##*/}"
			ln -s "$x" /usr/local/bin/"${x##*/}"
		fi
	done
	if [ ! -s $HOME_DIR/conf/server_block.acl ]; then
		Wget_get_files $HOME_DIR/conf/server_block.acl $URL/acl/server_block.acl
	fi
	if [ ! -s /etc/systemd/system/ss-main.service ]; then
		Wget_get_files /etc/systemd/system/ss-main.service $URL/init.d/ss-main.service
		chmod 0644 /etc/systemd/system/ss-main.service
		systemctl enable ss-main.service
		systemctl daemon-reload
		systemctl reset-failed
	fi
}

Author() {
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		echo -e "=========== \033[1mShadowsocks-rust\033[0m Multiport Management by \033[$(Generate_random_numbers 1 7);$(Generate_random_numbers 30 37);$(Generate_random_numbers 40 47)m爱翻墙的红杏\033[0m ==========="
	else
		echo -e "=========== \033[1mShadowsocks-rust\033[0m 多端口管理脚本 by \033[$(Generate_random_numbers 1 7);$(Generate_random_numbers 30 37);$(Generate_random_numbers 40 47)m爱翻墙的红杏\033[0m ==========="
	fi
}

Status() {
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		echo -e "Service Status: \c"
	else
		echo -e "服务状态: \c"
	fi
	local ssm dae
	if [ -s /run/ss-manager.pid ]; then
		read -r ssm </run/ss-manager.pid
	fi
	if [ -d /proc/"${ssm:=lzbx}" ]; then
		if [ -s /run/ss-daemon.pid ]; then
			read -r dae </run/ss-daemon.pid
		fi
		if [ -d /proc/"${dae:=lzbx}" ]; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				echo -e "\033[1;37;42mRuning\033[0m"
			else
				echo -e "\033[1;37;42m运行中\033[0m"
			fi
			runing=true
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				echo -e "\033[1;37;43mThe daemon is not running\033[0m"
			else
				echo -e "\033[1;37;43m守护脚本未运行\033[0m"
			fi
			Stop
		fi
	else
		if [[ "$(ssmanager -V)" == "shadowsocks"* ]]; then
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				echo -e "\033[1;37;41mStopped\033[0m"
			else
				echo -e "\033[1;37;41m未运行\033[0m"
			fi
			runing=false
		else
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				echo -e "\033[1;37;41mSystem incompatibility\033[0m"

			else
				echo -e "\033[1;37;41m系统或版本不兼容\033[0m"
			fi
			Uninstall
		fi
	fi
}

Obfs_plugin() {
	unset -v obfs
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "Which network traffic obfuscation you'd select"
	else
		Introduction "请选择流量混淆方式"
	fi
	local obfs_rust=(http tls)
	select obfs in "${obfs_rust[@]}"; do
		if [ "$obfs" ]; then
			Prompt "$obfs"
			break
		fi
	done
}

V2ray_plugin() {
	Create_certificate

	unset -v v2ray_mode
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "Which Transport mode you'd select"
	else
		Introduction "请选择传输模式"
	fi
	local mode_list=(websocket-http websocket-tls quic-tls grpc grpc-tls)
	select v2ray_mode in "${mode_list[@]}"; do
		if [ "$v2ray_mode" ]; then
			Prompt "$v2ray_mode"
			break
		fi
	done

	unset -v v2ray_path v2ray_servicename
	local v2ray_paths
	v2ray_paths=$(shasum -a1 /proc/sys/kernel/random/uuid)
	if [[ $v2ray_mode =~ "websocket-" ]]; then
		until [ "$v2ray_path" ]; do
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "URL path for websocket"
			else
				Introduction "请输入一个监听路径(url path)"
			fi
			read -rp "(${mr:=默认}: ${v2ray_paths%% *}): " v2ray_path
			if ! echo "$v2ray_path" | grep -qoE '^[A-Za-z0-9]+$'; then
				unset -v v2ray_path
			fi
			[ -z "$v2ray_path" ] && v2ray_path=${v2ray_paths%% *}
			#[ "${v2ray_path:0:1}" != "/" ] && v2ray_path="/$v2ray_path"
			Prompt "$v2ray_path"
		done
	fi
	if [ "$v2ray_mode" = "grpc-tls" ]; then
		until [ "$v2ray_servicename" ]; do
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "Service name for grpc(Requires client support otherwise please leave the default)"
			else
				Introduction "请输入gRPC服务的名称(需要客户端支持否则请保持默认)"
			fi
			read -rp "(${mr:=默认}: GunService): " v2ray_servicename
			if ! echo "$v2ray_servicename" | grep -qoE '^[A-Za-z0-9]+$'; then
				unset -v v2ray_servicename
			fi
			[ -z "$v2ray_servicename" ] && v2ray_servicename=GunService
			Prompt "$v2ray_servicename"
		done
	fi

}

Kcptun_plugin() {
	Introduction "key"
	unset -v kcp_key
	read -r kcp_key
	[ -z "$kcp_key" ] && kcp_key="$password"
	[ -z "$kcp_key" ] && kcp_key="it's a secrect"
	Prompt "$kcp_key"

	unset -v kcp_crypt
	Introduction "crypt"
	local crypt_list=(aes aes-128 aes-192 salsa20 blowfish twofish cast5 3des tea xtea xor sm4 none)
	select kcp_crypt in "${crypt_list[@]}"; do
		if [ "$kcp_crypt" ]; then
			Prompt "$kcp_crypt"
			break
		fi
	done

	unset -v kcp_mode
	Introduction "mode"
	local mode_list=(fast3 fast2 fast normal manual)
	select kcp_mode in "${mode_list[@]}"; do
		if [ "$kcp_mode" ]; then
			Prompt "$kcp_mode"
			break
		fi
	done

	unset -v kcp_mtu
	Introduction "mtu"
	read -rp "(${mr:=默认}: 1350): " kcp_mtu
	! is_number "$kcp_mtu" && kcp_mtu=1350
	Prompt "$kcp_mtu"

	unset -v kcp_sndwnd
	Introduction "sndwnd"
	read -rp "(${mr:=默认}: 1024): " kcp_sndwnd
	! is_number "$kcp_sndwnd" && kcp_sndwnd=1024
	Prompt "$kcp_sndwnd"

	unset -v kcp_rcvwnd
	Introduction "rcvwnd"
	read -rp "(${mr:=默认}: 1024): " kcp_rcvwnd
	! is_number "$kcp_rcvwnd" && kcp_rcvwnd=1024
	Prompt "$kcp_rcvwnd"

	unset -v kcp_datashard
	Introduction "datashard,ds"
	read -rp "(${mr:=默认}: 10): " kcp_datashard
	! is_number "$kcp_datashard" && kcp_datashard=10
	Prompt "$kcp_datashard"

	unset -v kcp_parityshard
	Introduction "parityshard,ps"
	read -rp "(${mr:=默认}: 3): " kcp_parityshard
	! is_number "$kcp_parityshard" && kcp_parityshard=3
	Prompt "$kcp_parityshard"

	unset -v kcp_dscp
	Introduction "dscp"
	read -rp "(${mr:=默认}: 0): " kcp_dscp
	! is_number "$kcp_dscp" && kcp_dscp=0
	Prompt "$kcp_dscp"

	unset -v kcp_nocomp
	Introduction "nocomp"
	select kcp_nocomp in true false; do
		if [ "$kcp_nocomp" ]; then
			Prompt "$kcp_nocomp"
			break
		fi
	done

	unset -v extra_parameters
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "After setting the basic parameters, do you need to set additional hidden parameters? (Y/N)"
	else
		Introduction "基础参数设置完成，你是否需要设置额外的隐藏参数? (Y/N)"
	fi
	read -rp "(${mr:=默认}: N): " -n1 extra_parameters
	echo
	if [[ $extra_parameters =~ ^[Yy]$ ]]; then
		unset -v kcp_acknodelay
		Introduction "acknodelay"
		select kcp_acknodelay in true false; do
			if [ "$kcp_acknodelay" ]; then
				Prompt "$kcp_acknodelay"
				break
			fi
		done

		unset -v kcp_nodelay
		Introduction "nodelay"
		read -rp "(${mr:=默认}: 0): " kcp_nodelay
		! is_number "$kcp_nodelay" && kcp_nodelay=0
		Prompt "$kcp_nodelay"

		unset -v kcp_interval
		Introduction "interval"
		read -rp "(${mr:=默认}: 30): " kcp_interval
		! is_number "$kcp_interval" && kcp_interval=30
		Prompt "$kcp_interval"

		unset -v kcp_resend
		Introduction "resend"
		read -rp "(${mr:=默认}: 2): " kcp_resend
		! is_number "$kcp_resend" && kcp_resend=2
		Prompt "$kcp_resend"

		unset -v kcp_nc
		Introduction "nc"
		read -rp "(${mr:=默认}: 1): " kcp_nc
		! is_number "$kcp_nc" && kcp_nc=1
		Prompt "$kcp_nc"
	fi
	echo
}

Shadowsocks_info_input() {
	unset -v server_port password method plugin
	local sport
	while true; do
		sport=$(Generate_random_numbers 1024 65535)
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Please enter a port"
		else
			Introduction "请输入Shadowsocks远程端口"
		fi
		read -rp "(${mr:=默认}: $sport): " -n5 server_port
		[ -z "$server_port" ] && server_port=$sport
		if is_number "$server_port" && [ "$server_port" -gt 0 ] && [ "$server_port" -le 65535 ]; then
			if is_number "$(Used_traffic "$server_port")"; then
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Prompt "The port is in normal use!"
				else
					Prompt "端口正常使用中！"
				fi
				unset -v server_port
				continue
			fi
			if netstat -ln | grep 'LISTEN' | grep -q ":$server_port "; then
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Prompt "The port is occupied by another process!"
				else
					Prompt "端口被其它进程占用！"
				fi
				unset -v server_port
				continue
			fi
			if [ -s $HOME_DIR/port.list ]; then
				while IFS= read -r line || [ -n "$line" ]; do
					IFS='|'
					for l in $line; do
						if [ "${l#*^}" = "$server_port" ]; then
							if [ ${Language:=zh-CN} = 'en-US' ]; then
								Prompt "The port already exists in the port list!"
							else
								Prompt "端口已存在于端口列表中！"
							fi
							unset -v server_port
							continue 3
						fi
					done
				done <$HOME_DIR/port.list
			fi
			if [ "$server_port" ]; then
				Prompt "$server_port"
				break
			fi
		fi
	done
	local ciphertext spass
	ciphertext=$(base64 -w0 /proc/sys/kernel/random/uuid)
	spass=${ciphertext:0:16}
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "Please enter a password"
	else
		Introduction "请输入Shadowsocks密码"
	fi
	read -rp "(${mr:=默认}: $spass): " password
	[ -z "$password" ] && password=$spass
	Prompt "$password"

	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "Which cipher you'd select"
	else
		Introduction "请选择Shadowsocks加密方式"
	fi
	select method in "${Encryption_method_list[@]}"; do
		if [ "$method" ]; then
			Prompt "$method"
			break
		fi
	done

	while true; do
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Please enter a value for the traffic limit (MB): "
		else
			Introduction "请输入端口流量配额 (MB): "
		fi
		read -r total
		if is_number "$total" && [ "$total" -gt 0 ]; then
			Prompt "$total MB"
			break
		fi
	done

	local add_plugin
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "Do you need to add a plugin? (Y/N)"
	else
		Introduction "需要加装插件吗? (Y/N)"
	fi
	read -rp "(${mr:=默认}: N): " -n1 add_plugin
	if [[ $add_plugin =~ ^[Yy]$ ]]; then
		echo -e "\r\n"
		plugin_list=(simple-obfs kcptun v2ray-plugin)
		select plugin in "${plugin_list[@]}"; do
			if [ "$plugin" ]; then
				Prompt "$plugin"
				break
			fi
		done
		if [ "$plugin" = 'simple-obfs' ]; then
			Obfs_plugin
		elif [ "$plugin" = 'kcptun' ]; then
			Kcptun_plugin
		elif [ "$plugin" = 'v2ray-plugin' ]; then
			V2ray_plugin
		fi
	fi
}

Client_Quantity() (
	i=0
	while IFS= read -r line; do
		((i++))
		[ "$i" -le 2 ] && continue #仅跳出当前循环
		unset -v proto recv send local_address foreign_address state program_name
		IFS=' '
		x=0
		for l in $line; do
			((x++))
			case $x in
			1)
				#proto=$l
				;;
			2)
				#recv=$l
				;;
			3)
				#send=$l
				;;
			4)
				local_address=$l
				;;
			5)
				foreign_address=$l
				;;
			6)
				state=$l
				;;
			7)
				#program_name=$l
				break
				;;
			esac
		done
		if [ "$state" = "ESTABLISHED" ]; then
			if [ "${local_address##*:}" = "$1" ]; then
				array_reme+=("${foreign_address%:*}")
			fi
		fi
	done <"$net_file"
	#uniq+=($(printf "%s\n" "${array_reme[@]}" | sort -u | tr '\n' ' '))
	for i in $(printf "%s\n" "${array_reme[@]}" | sort -u | tr '\n' ' '); do
		uniq+=("$i")
	done
	if [ "${#uniq[*]}" -ge 1 ]; then
		printf '%d' "${#uniq[@]}"
	fi
)

User_list_display() {
	local plugin_opt color temp_file net_file serial port tz a1 a2 a3 a4 a5 a6 a7 quantity used status total
	while true; do
		clear
		Check_permissions
		temp_file=$(mktemp)
		net_file=$(mktemp)
		if [ -s $HOME_DIR/port.list ]; then
			netstat -anp46 >"$net_file"
			serial=0
			#修复无法读取到最后一行的历史问题 https://stackoverflow.com/a/12916758
			while IFS= read -r line || [ -n "$line" ]; do
				Parsing_User "$line"
				if [ "$server_port" ]; then
					if [[ $plugin != "kcptun.sh" && $plugin_opts != *quic* ]]; then
						quantity=$(Client_Quantity "$server_port")
					else
						if [ ${Language:=zh-CN} = 'en-US' ]; then
							quantity='[yellow]Not supported[/yellow]'
						else
							quantity='[yellow]不支持[/yellow]'
						fi
					fi
					used=$(Used_traffic "$server_port")
					((serial++))
					if [ "$used" ] && [ "$used" -ge 0 ]; then
						if [ ${Language:=zh-CN} = 'en-US' ]; then
							status='[green]Normal[/green]'
						else
							status='[green]正常[/green]'
						fi
						tz=no
					else
						if [ ${Language:=zh-CN} = 'en-US' ]; then
							status='[red]Close[/red]'
						else
							status='[red]停止[/red]'
						fi
						used=0
						tz=yes
					fi
					if [ "$plugin" = "obfs-server" ]; then
						plugin='simple-obfs'
						plugin_opt=$(Parsing_plugin_opts "$plugin_opts" "obfs")
					elif [ "$plugin" = "kcptun.sh" ]; then
						plugin='kcptun'
						plugin_opt=$(Parsing_plugin_opts "$plugin_opts" "mode")
					elif [ "$plugin" = "v2ray-plugin" ]; then
						plugin='v2ray'
						case $plugin_opts in
						*'mode=grpc;tls;'*)
							plugin_opt='grpc-tls'
							;;
						*'mode=grpc;'*)
							plugin_opt='grpc'
							;;
						*'mode=quic;'*)
							plugin_opt='quic'
							;;
						*'server;tls;'*)
							plugin_opt='wss'
							;;
						*)
							plugin_opt='ws'
							;;
						esac
					fi
					[ -z "$total" ] && total=0
					color=$((used * 100 / total))
					if [ "$color" -ge 75 ] && [ "$color" -le 100 ]; then
						color="[red]$color %[/red]"
					elif [ "$color" -ge 50 ] && [ "$color" -le 75 ]; then
						color="[yellow]$color %[/yellow]"
					elif [ "$color" -ge 25 ] && [ "$color" -le 50 ]; then
						color="[green]$color %[/green]"
					elif [ "$color" -ge 0 ] && [ "$color" -le 25 ]; then
						color="[blue]$color %[/blue]"
					fi
					if [ "$tz" = "yes" ]; then
						a1="[italic strike bold red]${serial:-0}[/italic strike bold red]"
						a2="[strike bold red]${server_port:-0}[/strike bold red]"
						a4="[strike bold red]$(traffic $used) / $(traffic $total)[/strike bold red]"
					else
						a1="[italic]${serial:-0}[/italic]"
						a2="${server_port:-0}"
						a4="$(traffic $used) / $(traffic $total)"
					fi
					if [ "$plugin_opt" ]; then
						a3="${plugin}[white bold]/[/white bold][#00ffff]${plugin_opt}[/#00ffff]"
					else
						a3="$plugin"
					fi
					a5="${color:-0}"
					a6="$quantity"
					a7="$status"
					echo "$a1,$a2,$a3,$a4,$a5,$a6,$a7" >>"$temp_file"
				fi
				unset -v quantity used status color tz plugin_opt a1 a2 a3 a4 a5 a6 a7
			done <$HOME_DIR/port.list
			${python:=python3} <<-EOF
				from rich.console import Console
				from rich.table import Table
				if "${Language:=zh-CN}" == 'zh-CN':
				  table = Table(title="用户列表", caption="$(TZ='Asia/Shanghai' date +%Y年%m月%d日\ %X)", show_lines=True)
				  table.add_column("序号", justify="left", no_wrap=True)
				  table.add_column("端口", justify="center", style="#66ccff")
				  table.add_column("传输插件", justify="center", style="#ee82ee", no_wrap=True)
				  table.add_column("流量", justify="center")
				  table.add_column("使用率", justify="center")
				  table.add_column("客户端数量", justify="center")
				  table.add_column("状态", justify="right")
				else:
				  table = Table(title="User List", caption="$(date +'%A %B %d %T %y')", show_lines=True)
				  table.add_column("Top", justify="left", no_wrap=True)
				  table.add_column("Port", justify="center", style="#66ccff")
				  table.add_column("Plug-in", justify="center", style="#ee82ee", no_wrap=True)
				  table.add_column("Network traffic", justify="center")
				  table.add_column("Usage rate", justify="center")
				  table.add_column("Client", justify="center")
				  table.add_column("Status", justify="right")
				with open("$temp_file", 'r') as fd:
				  for lines in fd.read().splitlines():   
				    a, b, c, d, e, f, g = lines.split(',')
				    table.add_row(a, b, c, d, e, f, g)    
				console = Console()
				console.print(table, justify="center")
			EOF
		fi
		rm -f "$net_file" "$temp_file"
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			cat <<EOF
1. Add a Port
2. Delete a Port
3. Activate a port
4. Forcing a Port offline
EOF
			read -rp $'Please enter a number \e[95m1-3\e[0m: ' -n1 action
		else
			cat <<EOF
1. 添加端口
2. 删除端口
3. 激活端口
4. 离线端口
EOF
			read -rp $'请选择 \e[95m1-3\e[0m: ' -n1 action
		fi
		echo
		case $action in
		1)
			Add_user
			;;
		2)
			Delete_users
			;;
		3)
			while true; do
				if [ ${Language:=zh-CN} = 'en-US' ]; then
					Introduction "Please enter the port to be activated"
				else
					Introduction "请输入需要激活的端口"
				fi
				read -rn5 port
				if is_number "$port" && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; then
					Upload_users "$port"
					break
				fi
			done
			;;
		4)
			Forced_offline
			;;
		*)
			break
			;;
		esac
	done
}

Add_user() {
	Address_lookup
	Shadowsocks_info_input
	Press_any_key_to_continue
	clear
	local userinfo qrv4 qrv6 name plugin_url ss_info=() ss_link=()
	if [ "$ipv4" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			ss_info+=("Your_Server_IP(IPv4)+$ipv4")
		else
			ss_info+=("服务器(IPv4)+$ipv4")
		fi
	fi
	if [ "$ipv6" ]; then
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			ss_info+=("Your_Server_IP\(IPv6\)+$ipv6")
		else
			ss_info+=("服务器\(IPv6\)+$ipv6")
		fi
	fi
	if [ "$ipv4" ] || [ "$ipv6" ]; then
		userinfo="$(echo -n "$method:$password" | base64 -w0 | sed 's/=//g; s/+/-/g; s/\//_/g')"
		#websafe-base64-encode-utf8 不兼容标准的的base64
		#https://www.liaoxuefeng.com/wiki/1016959663602400/1017684507717184
	fi
	name=$(Url_encode "$addr")
	if [ "${Language:=zh-CN}" = 'en-US' ]; then
		ss_info+=("Your_Server_Port+$server_port")
		ss_info+=("Your_Password+$password")
		ss_info+=("Your_Encryption_Method+$method")
	else
		ss_info+=("远程端口+$server_port")
		ss_info+=("密码+$password")
		ss_info+=("加密方式+$method")
	fi
	case $plugin in
	simple-obfs)
		ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\",\"plugin\":\"obfs-server\",\"plugin_opts\":\"obfs=$obfs\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^obfs-server|plugin_opts^obfs=$obfs|total^$((total * 1048576))" >>$HOME_DIR/port.list
		plugin_url="/?plugin=$(Url_encode "obfs-local;obfs=$obfs;obfs-host=checkappexec.microsoft.com")"
		;;
	kcptun)
		local kcp_nocomps kcp_acknodelays
		[ "$kcp_nocomp" = "true" ] && kcp_nocomps=';nocomp'
		[ "$kcp_acknodelay" = "true" ] && kcp_acknodelays=';acknodelay'
		if [[ $extra_parameters =~ ^[Yy]$ ]]; then
			ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"kcptun.sh\",\"plugin_opts\":\"key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays\"}" >/dev/null
			echo "server_port^$server_port|password^$password|method^$method|plugin^kcptun.sh|plugin_opts^key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays|total^$((total * 1048576))" >>$HOME_DIR/port.list
			plugin_url="/?plugin=$(Url_encode "kcptun;key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays")"
		else
			ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"kcptun.sh\",\"plugin_opts\":\"key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps\"}" >/dev/null
			echo "server_port^$server_port|password^$password|method^$method|plugin^kcptun.sh|plugin_opts^key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps|total^$((total * 1048576))" >>$HOME_DIR/port.list
			plugin_url="/?plugin=$(Url_encode "kcptun;key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps")"
		fi
		;;
	v2ray-plugin)
		local v2ray_modes v2ray_certraw v2ray_client qui
		v2ray_certraw=$(sed '1d;$d' $tls_cert)
		case $v2ray_mode in
		websocket-http)
			v2ray_modes="server;path=$v2ray_path;host=$tls_common_name"
			v2ray_client="path=$v2ray_path;host=$tls_common_name"
			;;
		websocket-tls)
			v2ray_modes="server;tls;path=$v2ray_path;host=$tls_common_name;key=$tls_key;cert=$tls_cert"
			v2ray_client="tls;path=$v2ray_path;host=$tls_common_name;certRaw=$v2ray_certraw"
			;;
		quic-tls)
			v2ray_modes="server;mode=quic;host=$tls_common_name;key=$tls_key;cert=$tls_cert"
			v2ray_client="mode=quic;host=$tls_common_name;certRaw=$v2ray_certraw"
			qui='tcp_only'
			;;
		grpc)
			v2ray_modes="server;mode=grpc;host=$tls_common_name;serviceName=$v2ray_servicename;key=$tls_key;cert=$tls_cert"
			v2ray_client="mode=grpc;host=$tls_common_name;serviceName=$v2ray_servicename;certRaw=$v2ray_certraw"
			;;
		grpc-tls)
			v2ray_modes="server;mode=grpc;tls;host=$tls_common_name;serviceName=$v2ray_servicename;key=$tls_key;cert=$tls_cert"
			v2ray_client="tls;mode=grpc;host=$tls_common_name;serviceName=$v2ray_servicename;certRaw=$v2ray_certraw"
			;;
		esac
		ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"${qui:=tcp_and_udp}\",\"plugin\":\"v2ray-plugin\",\"plugin_opts\":\"$v2ray_modes\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^v2ray-plugin|plugin_opts^$v2ray_modes|total^$((total * 1048576))" >>$HOME_DIR/port.list
		plugin_url="/?plugin=$(Url_encode "v2ray-plugin;$v2ray_client")"
		;;
	*)
		ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^|plugin_opts^|total^$((total * 1048576))" >>$HOME_DIR/port.list
		;;
	esac
	if [ "$plugin" ]; then
		if [ "${Language:=zh-CN}" == 'en-US' ]; then
			ss_info+=("Your_Transport_Plugin+$plugin")
		else
			ss_info+=("传输插件+$plugin")
		fi
	fi
	if [ "$plugin" ]; then
		if [ "$userinfo" ] && [ "$ipv4" ]; then
			qrv4="ss://$userinfo@$ipv4:$server_port$plugin_url#$name"
			ss_link+=("$qrv4")
		fi
		if [ "$userinfo" ] && [ "$ipv6" ]; then
			qrv6="ss://$userinfo@[${ipv6}]:$server_port$plugin_url#$name"
			ss_link+=("$qrv6")
		fi
	else
		if [ "$userinfo" ] && [ "$ipv4" ]; then
			qrv4="ss://$userinfo@$ipv4:$server_port#$name"
			ss_link+=("$qrv4")
		fi
		if [ "$userinfo" ] && [ "$ipv6" ]; then
			qrv6="ss://$userinfo@[${ipv6}]:$server_port#$name"
			ss_link+=("$qrv6")
		fi
	fi
	${python:=python3} <<-EOF
		from rich import print as rprint
		from rich.console import group
		from rich.panel import Panel
		from rich.table import Table
		from random import choice
		from os import get_terminal_size

		ss_message = Table.grid(padding=1)
		ss_message.add_column(style="bold", justify="left")
		ss_message.add_column(no_wrap=True, style="bold red")
		arr = "${ss_info[@]}"
		list2 = []
		for ss in arr.split(' '):
		  key, val = ss.split('+')
		  ss_message.add_row(
		    key,
		    val
		  )

		@group()
		def get_panels():
		    list1 = ['#66ccff', '#ee82ee', '#39c5bb', '#ffc0cb']
		    color = 'bold ' + choice(list1)
		    yield Panel(ss_message, style=color)
		    arr = "${ss_link[@]}"      
		    for link in arr.split(' '):
		      #color = 'italic bold on ' + choice(list1)
		      color = 'bold ' + choice(list1)
		      #https://xrlin.github.io/使用textwrap模块进行字符串的指定宽度输出/
		      if len(link) <= get_terminal_size().columns:
		        yield Panel(link, style=color)
		      else:
		        list2.append(link)
		if "${Language:=zh-CN}" == 'zh-CN':
		  rprint(Panel(get_panels(), title="配置信息", subtitle="以上信息请拿笔记好！"))
		else:
		  rprint(Panel(get_panels(), title="Configuration Information", subtitle="Please take note of the above information!"))
		for x in list2:
		  print('\033[4;1;35m'+x+'\033[0m')
	EOF
	echo
	if [ "$v2ray_modes" ] && [ "$v2ray_modes" != "quic-tls" ]; then
		Reload_nginx
	fi
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "Do you still need to display QR codes and client profiles?"
	else
		Introduction "需要显示二维码和客户端配置文件吗？"
	fi
	read -rp "(${mr:=默认}: N): " -n1 qrv
	if [[ $qrv =~ ^[Yy]$ ]]; then
		clear
		if [ "$qrv4" ]; then
			ssurl -d "$qrv4"
			qrencode -m 2 -l L -t ANSIUTF8 -k "$qrv4"
		fi
		if [ "$qrv6" ]; then
			ssurl -d "$qrv6"
			qrencode -m 2 -l L -t ANSIUTF8 -k "$qrv6"
		fi
	fi
	echo
	Press_any_key_to_continue
}

Delete_users() {
	if [ -s $HOME_DIR/port.list ]; then
		port=$1
		until [ "$port" ]; do
			if [ ${Language:=zh-CN} = 'en-US' ]; then
				Introduction "Please enter the user port to be deleted"
			else
				Introduction "请输入需要删除的端口"
			fi
			read -rn5 port
			if is_number "$port" && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; then
				break
			else
				unset -v port
			fi
		done
		local temp_file pz1 pz2
		temp_file=$(mktemp)
		while IFS= read -r line || [ -n "$line" ]; do
			Parsing_User "$line"
			if is_number "$server_port" && is_number $total; then
				if [[ $server_port -ne $port && $server_port -gt 0 && $server_port -lt 65535 && $password && $method && $total -gt 0 ]]; then
					echo "server_port^$server_port|password^$password|method^$method|plugin^$plugin|plugin_opts^$plugin_opts|total^$total" >>"$temp_file"
				fi
				if [ "$server_port" -eq "$port" ]; then
					ss-tool /tmp/ss-manager.socket "remove: {\"server_port\":$port}" >/dev/null
					pz1=$plugin
					pz2=$plugin_opts
				fi
			fi
		done <$HOME_DIR/port.list
		mv -f "$temp_file" $HOME_DIR/port.list
		echo
		if [[ $pz1 == "v2ray-plugin" && $pz2 != *quic* ]]; then
			Reload_nginx
		fi
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "No port list file found"
		else
			Prompt "没有找到端口列表文件"
		fi
		Press_any_key_to_continue
	fi
}

Upload_users() {
	if [ -s $HOME_DIR/port.list ]; then
		local using
		while IFS= read -r line || [ -n "$line" ]; do
			Parsing_User "$line"
			[ "$1" ] && [ "$1" != "$server_port" ] && continue
			using=$(Used_traffic "$server_port")
			if is_number "$server_port" && is_number "$total" && [ -z "$using" ] && [ "$password" ] && [ "$method" ]; then
				if [ "$plugin" ] && [ "$plugin_opts" ]; then
					if [[ $plugin == "kcptun.sh" || $plugin_opts == *quic* ]]; then
						ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"$plugin\",\"plugin_opts\":\"$plugin_opts\"}" >/dev/null
					else
						ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\",\"plugin\":\"$plugin\",\"plugin_opts\":\"$plugin_opts\"}" >/dev/null
					fi
				else
					ss-tool /tmp/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_and_udp\"}" >/dev/null
				fi
			fi
			unset -v using
		done <$HOME_DIR/port.list
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "No port list file found! Please add a user port first."
		else
			Prompt "没有找到端口列表文件！请先添加端口。"
		fi
		Press_any_key_to_continue
	fi
}

Forced_offline() {
	while true; do
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Introduction "Please enter the port of the user who needs to be forced offline"
		else
			Introduction "请输入需要离线的端口"
		fi
		read -rn5 port
		if is_number "$port" && [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; then
			ss-tool /tmp/ss-manager.socket "remove: {\"server_port\":$port}" >/dev/null
			break
		fi
	done
}

Daemon() {
	if [ -r /run/ss-daemon.pid ]; then
		pkill -F /run/ss-daemon.pid 2>/dev/null
	fi
	echo $NOW_PID >/run/ss-daemon.pid
	local flow
	if [ -r /run/ss-manager.pid ] && [ -r /run/ss-daemon.pid ]; then
		read -r pid1 </run/ss-manager.pid
		read -r pid2 </run/ss-daemon.pid
		if is_number "$pid1" && is_number "$pid2"; then
			while [ -d /proc/"${pid1:=lzbx}" ] && [ -d /proc/"${pid2:=lzbx}" ]; do
				if [ -s $HOME_DIR/port.list ]; then
					while IFS= read -r line || [ -n "$line" ]; do
						Parsing_User "$line"
						flow=$(Used_traffic "$server_port")
						if is_number "$server_port" && is_number "$flow" && is_number $total; then
							if [ "${flow:-0}" -ge ${total:-0} ]; then
								Delete_users "$server_port" >/dev/null
							fi
							unset -v flow
						fi
					done <$HOME_DIR/port.list
				fi
				sleep 1
			done
		fi
	fi
}

Start() {
	Local_IP
	if [ ${runing:-false} = true ]; then
		if [ "${Language:=zh-CN}" = "en-US" ]; then
			Prompt "Please stop first when the service is running!"
		else
			Prompt "服务运行中请先停止运行!"
		fi
		Press_any_key_to_continue
	else
		local cs=60 #6秒启动超时与重试 https://github.com/shadowsocks/shadowsocks-rust/issues/587
		[ "$ipv6" ] && local first_v6='-6'
		ssmanager \
			--acl ${HOME_DIR:?}/conf/server_block.acl \
			--manager-address /tmp/ss-manager.socket \
			--server-host "${ipv4:-$ipv6}" \
			--outbound-bind-addr "${ipv4:-$ipv6}" \
			--daemonize-pid /run/ss-manager.pid \
			--daemonize $first_v6
		while true; do
			((cs--))
			if [ ${cs:-0} -eq 0 ]; then
				if [ "${Language:=zh-CN}" = "en-US" ]; then
					Prompt "Timeout to start ssmanager!"
				else
					Prompt "启动ssmanager超时!"
				fi
				Stop
				Exit
			else
				if ss-tool /tmp/ss-manager.socket ping >/dev/null 2>&1; then
					break
				fi
				sleep 0.1
			fi
		done
		if [ -S /tmp/ss-manager.socket ] && [ -s /run/ss-manager.pid ]; then
			Upload_users
			(setsid ss-main daemon >/dev/null 2>&1 &)
			cs=30 #3秒超时，需要等待后台守护脚本启动完成
			until [ -s /run/ss-daemon.pid ]; do
				((cs--))
				if [ ${cs:-0} -eq 0 ]; then
					if [ "${Language:=zh-CN}" = "en-US" ]; then
						Prompt "Daemon start timeout!"
					else
						Prompt "守护脚本启动超时!"
					fi
					Stop
					Exit
				else
					sleep 0.1
				fi
			done
			Reload_nginx
		fi
	fi
}

Stop() {
	for i in /run/ss-manager.pid /run/ss-daemon.pid; do
		[ -s $i ] && read -r kpid <$i
		[ -d /proc/"${kpid:=lzbx}" ] && kill "$kpid" && rm -f $i
	done
}

Update_core() {
	local temp_file temp_file2 update
	temp_file=$(mktemp) temp_file2=$(mktemp)
	Wget_get_files "$temp_file" $URL/version/update
	#sed -i "s=*bin=$HOME_DIR/usr/bin=" $temp_file
	! shasum -a512 -c "$temp_file" >>"$temp_file2" && update=true || update=false
	sed -i 's/: /,/g' "$temp_file2"
	${python:=python3} <<-EOF
		from rich.console import Console
		from rich.table import Table
		if "${Language:=zh-CN}" == 'zh-CN':
		  table = Table(title="程序升级列表", show_lines=True)
		  table.add_column("文件路径", justify="left", no_wrap=True)
		  table.add_column("更新状态", justify="right")
		else:
		  table = Table(title="Upgrade List", show_lines=True)
		  table.add_column("Binary program path", justify="left", no_wrap=True)
		  table.add_column("Upgrade Status", justify="right")
		with open("$temp_file2", 'r') as fd:
		  for lines in fd.read().splitlines():   
		    a, b = lines.split(',')
		    if 'OK' in b:
		      b = '[bold green]' + b + '[/bold green]'
		    elif 'FAILED' in b:
		      b = '[bold yellow]' + b + '[/bold yellow]'
		    table.add_row(a, b)    
		console = Console()
		console.print(table, justify="left")
	EOF
	rm -f "$temp_file" "$temp_file2"
	if $update; then
		rm -rf ${HOME_DIR:?}/usr ${HOME_DIR:?}/conf
		Check
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Please restart all services of this script manually to apply the update."
		else
			Prompt "请手动重启本脚本的所有服务以应用更新。"
		fi
		Exit
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "No updates found!"
		else
			Prompt "未发现任何更新！"
		fi
	fi
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		echo -e "\e[1mHelp and Feedback: \e[0m\e[1;34mhttps://github.com/yiguihai/shadowsocks_install\e[0m\n"
	else
		echo -e "\e[1m帮助与反馈: \e[0m\e[1;34mhttps://github.com/yiguihai/shadowsocks_install\e[0m\n"
	fi
	Press_any_key_to_continue
}

Uninstall() {
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		Introduction "Are you sure you want to uninstall? (Y/N)"
	else
		Introduction "确定要卸载吗? (Y/N)"
	fi
	read -rp "(${mr:=默认}: N): " -n1 delete
	if [[ $delete =~ ^[Yy]$ ]]; then
		systemctl stop ss-main.service
		systemctl disable ss-main.service
		rm -f /etc/systemd/system/ss-main.service
		systemctl daemon-reload
		systemctl reset-failed
		Stop
		Close_traffic_forward
		rm -rf $HOME_DIR
		rm -f "$0"
		rm -f /usr/local/bin/ss-main
		"${HOME}"/.acme.sh/acme.sh --uninstall
		rm -rf "${HOME}"/.acme.sh
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "Uninstallation is complete! (It is better to reboot the system)"
		else
			Prompt "已卸载！(最好重启一下)"
		fi
		Exit
	else
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			Prompt "已取消操作..."
		else
			Prompt "Canceled operation..."
		fi
	fi
	Exit
}

ShadowsocksR_Link_Decode() {
	local link a b server_port protocol method obfs password other obfsparam protoparam #remarks group
	read -rp "请输入SSR链接: " link
	[[ $link != "ssr://"* || -z $link ]] && Exit
	a=${link#ssr\:\/\/}
	b=$(echo "$a" | base64 -d 2>&-)
	i=0
	IFS=':'
	for c in ${b%\/}; do
		((i++))
		case $i in
		1)
			server=$c
			;;
		2)
			server_port=$c
			;;
		3)
			protocol=$c
			;;
		4)
			method=$c
			;;
		5)
			obfs=$c
			;;
		6)
			password=$(echo "${c%\/\?*}" | base64 -d 2>&-) #再解一次base64被坑了好久
			other=${c#*\/\?}
			;;
		esac
	done
	IFS='&'
	for d in $other; do
		case ${d%\=*} in
		obfsparam)
			obfsparam=$(echo "${d#*\=}" | base64 -d 2>&-)
			;;
		protoparam)
			protoparam=$(echo "${d#*\=}" | base64 -d 2>&-)
			;;
		remarks)
			#remarks=${d#*\=} #不解码了不规范的命名会乱码
			break
			;;
		group)
			#group=${d#*\=}
			break
			;;
		esac
	done
	cat >/tmp/ssr-redir.conf <<EOF
{
    "server":"$server",
    "server_port":$server_port,
    "method":"$method",
    "password":"$password",
    "protocol":"$protocol",
    "protocol_param":"$protoparam",
    "obfs":"$obfs",
    "obfs_param":"$obfsparam",
    "user":"nobody",
    "fast_open":false,
    "nameserver":"1.1.1.1",
    "mode":"tcp_only",
    "local_address":"127.0.0.1",
    "local_port":1088,
    "timeout":30
}
EOF
	cat /tmp/ssr-redir.conf
}

Close_traffic_forward() {
	iptables -w -t nat -D OUTPUT -j SHADOWSOCKS
	iptables -w -t nat -F SHADOWSOCKS
	iptables -w -t nat -X SHADOWSOCKS
	ipset destroy ipv4_lan
	ipset destroy traffic_forward
	pkill -F /run/ssr-redir.pid && rm -f /run/ssr-redir.pid
}

Start_traffic_forward() {
	[ ! -s /tmp/ssr-redir.conf ] && Exit
	ssr-redir -c /tmp/ssr-redir.conf -f /run/ssr-redir.pid || Exit
	rm -f /tmp/ssr-redir.conf
	local ipv4_lan=(
		0.0.0.0/8
		10.0.0.0/8
		100.64.0.0/10
		127.0.0.0/8
		169.254.0.0/16
		172.16.0.0/12
		192.0.0.0/24
		192.0.2.0/24
		192.88.99.0/24
		192.168.0.0/16
		198.18.0.0/15
		198.51.100.0/24
		203.0.113.0/24
		224.0.0.0/4
		240.0.0.0/4
		255.255.255.255/32
		"$server"/32
	)
	iptables -w -t nat -N SHADOWSOCKS
	ipset create ipv4_lan hash:net
	for i in "${ipv4_lan[@]}"; do
		ipset add ipv4_lan "$i"
	done
	ipset create traffic_forward hash:net
	iptables -w -t nat -A SHADOWSOCKS -p tcp -m set --match-set ipv4_lan dst -j RETURN
	#iptables -w -t nat -A SHADOWSOCKS -m owner --uid-owner nobody -j ACCEPT
	#iptables -w -t nat -A SHADOWSOCKS -p tcp -j LOG --log-prefix='[netfilter] '
	#grep 'netfilter' /var/log/kern.log
	iptables -w -t nat -A SHADOWSOCKS -p tcp -m set --match-set traffic_forward dst -j REDIRECT --to-ports 1088
	iptables -w -t nat -A OUTPUT -j SHADOWSOCKS
}

Start_nginx_program() {
	Create_certificate
	local dl=()
	if [ ! -f $HOME_DIR/usr/bin/nginx ] || [ ! -x $HOME_DIR/usr/bin/nginx ]; then
		dl+=("$URL/usr/sbin/nginx+$HOME_DIR/usr/bin/nginx")
	fi
	if [ ! -f $HOME_DIR/usr/bin/php-fpm ] || [ ! -x $HOME_DIR/usr/bin/php-fpm ]; then
		dl+=("$URL/usr/sbin/php-fpm+$HOME_DIR/usr/bin/php-fpm")
	fi
	if [ ! -d $HOME_DIR/usr/logs ]; then
		mkdir -p $HOME_DIR/usr/logs
	else
		rm -rf $HOME_DIR/usr/logs/*
	fi
	if [ ! -f $HOME_DIR/conf/cdn_only.conf ]; then
		touch $HOME_DIR/conf/cdn_only.conf
	fi
	if [ -s $HOME_DIR/port.list ]; then
		rm -f $HOME_DIR/conf/v2ray_list.conf
		while IFS= read -r line || [ -n "$line" ]; do
			Parsing_User "$line"
			if [[ $plugin == "v2ray-plugin" && $plugin_opts != *quic* ]]; then
				unset -v v2_protocols v2_protocols2
				if [[ $plugin_opts == *tls* ]]; then
					local v2_protocols='https'
					local v2_protocols2='grpcs'
				else
					local v2_protocols='http'
					local v2_protocols2='grpc'
				fi
				if [[ $plugin_opts == *grpc* ]]; then
					if [ "$v2_protocols2" = "grpcs" ]; then
						#https://www.v2fly.org/config/transport/grpc.html#grpcobject
						cat >>$HOME_DIR/conf/v2ray_list.conf <<-EOF

							location /$(Parsing_plugin_opts "$plugin_opts" "serviceName")/Tun {
							    include    v2safe.conf;
							    grpc_pass ${v2_protocols2}://${ipv4:-[$ipv6]}:${server_port};
							}
							    
						EOF
					fi
				else
					cat >>$HOME_DIR/conf/v2ray_list.conf <<-EOF

						location /$(Parsing_plugin_opts "$plugin_opts" "path") {
						    include    v2safe.conf;
						    proxy_pass ${v2_protocols}://${ipv4:-[$ipv6]}:${server_port};
						    include    proxy.conf;
						}
						    
					EOF
				fi
			fi
		done <$HOME_DIR/port.list
	else
		Prompt "没有找到端口列表文件"
		Exit
	fi
	if [ -z "$tls_common_name" ]; then
		Prompt "无法获取域名信息！"
		Exit
	fi
	if [ ! -s $HOME_DIR/conf/mime.types ]; then
		dl+=("$URL/usr/conf/mime.types+$HOME_DIR/conf/mime.types")
	fi
	for i in v2safe.conf add_header.conf v2ray-plugin.conf proxy.conf nginx.conf general.conf fastcgi_params.conf php-fpm.conf www.conf; do
		if [ ! -s $HOME_DIR/conf/$i ]; then
			dl+=("$URL/conf/$i+$HOME_DIR/conf/$i")
		fi
	done
	for i in 50x.html index.html; do
		if [ ! -s $HOME_DIR/web/$i ]; then
			dl+=("$URL/usr/html/$i+$HOME_DIR/web/$i")
		fi
	done
	if [ "${#dl[@]}" -gt 0 ]; then
		downloader "${dl[@]}"
		chmod +x "$HOME_DIR"/usr/bin/nginx "$HOME_DIR"/usr/bin/php-fpm
	fi
	for i in "${dl[@]}"; do
		if [ ! -f "${i##*+}" ]; then
			Prompt "文件 ${i##*+} 下载失败！"
			Exit
		fi
	done
	sed -i "/server_name/c\    server_name         $tls_common_name;" $HOME_DIR/conf/v2ray-plugin.conf
	#groupadd web
	#useradd -g web nginx -M -s /sbin/nologin
	if [ "$1" = "reload" ]; then
		if nginx -c $HOME_DIR/conf/nginx.conf -t >/dev/null 2>&1; then
			#Nginx动态加载配置，查询配置中的PID文件向其发送reload信号。
			if ! nginx -s reload -c $HOME_DIR/conf/nginx.conf; then
				Prompt "Nginx热重启失败!"
				Exit
			fi
		else
			Prompt "请检查Nginx配置是否有误"
			Exit
		fi
	else
		if nginx -c $HOME_DIR/conf/nginx.conf -t; then
			if nginx -c $HOME_DIR/conf/nginx.conf; then
				if php-fpm -n -y $HOME_DIR/conf/php-fpm.conf -R; then
					Prompt "现在可以访问你的域名 https://$tls_common_name 了"
				else
					Prompt "请检查PHP-FPM配置是否有误"
					Exit
				fi
			else
				Prompt "启动Nginx时出现未知错误"
				Exit
			fi
		else
			Prompt "请检查Nginx配置是否有误"
			Exit
		fi
	fi
}

Reload_nginx() {
	local ngx
	if [ -s /run/nginx.pid ]; then
		read -r ngx </run/nginx.pid
	fi
	if [ -d /proc/"${ngx:=lzbx}" ]; then
		Start_nginx_program reload
	fi
}

Advanced_features() {
	local two=0
	while true; do
		((two++))
		if [ "$two" -le 1 ]; then
			#免费节点
			#https://lncn.org/
			#https://m.ssrtool.us/free_ssr
			if [ ! -f $HOME_DIR/usr/bin/ssr-redir ] || [ ! -x $HOME_DIR/usr/bin/ssr-redir ]; then
				Wget_get_files $HOME_DIR/usr/bin/ssr-redir $URL/usr/bin/ss-redir
				chmod +x $HOME_DIR/usr/bin/ssr-redir
			fi
		fi
		local srd ngx pfm ret_code ssr_on
		if [ -s /run/ssr-redir.pid ]; then
			read -r srd </run/ssr-redir.pid
		fi
		if [ -d /proc/"${srd:=lzbx}" ]; then
			ret_code=$(curl --silent --output /dev/null --write-out '%{http_code}' --connect-timeout 2 --max-time 4 --url https://www.google.com)
			#https://stackoverflow.com/a/28356429
			if [[ ${ret_code:-0} != +(200|301|302) ]]; then
				echo -e '\033[7;31;43m无法访问Google请尝试切换或者关闭代理！\033[0m'
			fi
			echo -e "\033[1mssr-redir运行中 PID: \033[0m\033[7m$srd\033[0m"
			ssr_on="true"
		else
			ssr_on="false"
		fi
		if [ -s /run/nginx.pid ]; then
			read -r ngx </run/nginx.pid
		fi
		if [ -d /proc/"${ngx:=lzbx}" ]; then
			if [ -s $HOME_DIR/ssl/fullchain.cer ]; then
				if ! openssl x509 -checkend 86400 -noout -in $HOME_DIR/ssl/fullchain.cer >/dev/null; then
					if [ ${Language:=zh-CN} = 'en-US' ]; then
						echo -e '\033[7;31;43mCertificate has expired or will do so within 24 hours!\033[0m'
					else
						echo -e '\033[7;31;43m证书已过期或将在24小时内过期!\033[0m'
					fi
				fi
			fi
			echo -e "\033[1mNginx运行中 PID: \033[0m\033[7m$ngx\033[0m"
			nginx_on="--webroot ${HOME_DIR}/ssl"
		else
			nginx_on="--standalone"
		fi
		if [ -s /run/php-fpm.pid ]; then
			read -r pfm </run/php-fpm.pid
		fi
		if [ -d /proc/"${pfm:=lzbx}" ]; then
			echo -e "\033[1mPHP-FPM运行中 PID: \033[0m\033[7m$pfm\033[0m"
		fi
		cat <<EOF
—————————————— 服务器发出流量代理 ——————————————
1. 打开代理
2. 关闭代理
3. SSR链接解析
4. 添加IP地址
5. 添加Google网段
6. 添加Cloudflare网段
7. 清空IP列表
8. 查看IP列表
9. 查看iptables规则链状态
10. 80,443全局流量代理
—————————————— CDN中转+Nginx分流 ——————————————
11. 开启Nginx
12. 关闭Nginx
13. 重新申请证书
14. 更换网站模板
15. 仅限通过CDN访问
16. 订阅管理
—————————————— 脚本设置 ——————————————
17. 双栈切换
EOF
		read -rp $'请选择 \e[95m1-17\e[0m: ' -n2 action
		echo
		case $action in
		1)
			if [ "$ssr_on" = "false" ]; then
				ShadowsocksR_Link_Decode
				Start_traffic_forward
			else
				Prompt "服务运行中请先停止运行!"
			fi
			;;
		2)
			Close_traffic_forward
			;;
		3)
			ShadowsocksR_Link_Decode
			;;
		4)
			read -rp "请输入IP地址: " aip
			ipset add traffic_forward "$aip"
			;;
		5)
			#https://support.google.com/a/answer/10026322?hl=zh-Hans#
			local google_ipv4_ranges
			google_ipv4_ranges=$(curl --silent --connect-timeout 5 https://www.gstatic.com/ipranges/goog.json | jq -r '.prefixes[].ipv4Prefix' | tr '\n' '@') && {
				IFS='@'
				for i in $google_ipv4_ranges; do
					if [ "$i" != 'null' ]; then
						[ "$i" ] && ipset add traffic_forward "$i"
					fi
				done
			}
			;;
		6)
			local cloudflare_ipv4_ranges
			cloudflare_ipv4_ranges=$(curl --silent --connect-timeout 5 https://www.cloudflare.com/ips-v4 | grep -oE '([0-9]+\.){3}[0-9]+?\/[0-9]+?' | tr '\n' '@') && {
				IFS='@'
				for i in $cloudflare_ipv4_ranges; do
					[ "$i" ] && ipset add traffic_forward "$i"
				done
			}
			;;
		7)
			ipset flush traffic_forward
			;;
		8)
			ipset list traffic_forward
			;;
		9)
			iptables -vxn -t nat -L SHADOWSOCKS --line-number
			;;
		10)
			iptables -w -t nat -R SHADOWSOCKS 2 -p tcp -m multiport --dport 80,443 -j REDIRECT --to-ports 1088
			;;
		11)
			if [ "$nginx_on" = "--standalone" ]; then
				if ! netstat -ln | grep 'LISTEN' | grep -q ':80 \|:443 '; then
					Start_nginx_program
				else
					Prompt "80或443端口被其它进程占用！"
				fi
			else
				Prompt "服务运行中请先停止运行!"
			fi
			;;
		12)
			pkill -F /run/nginx.pid && rm -f /run/nginx.pid
			pkill -F /run/php-fpm.pid && rm -f /run/php-fpm.pid
			;;
		13)
			openssl x509 -dates -noout -in $HOME_DIR/ssl/fullchain.cer
			#openssl x509 -enddate -noout -in $HOME_DIR/ssl/fullchain.cer #过期日
			Introduction "确定要更新吗? (Y/N)"
			read -rp "(${mr:=默认}: N): " -n1 delete
			if [[ $delete =~ ^[Yy]$ ]]; then
				rm -f $HOME_DIR/ssl/*
				Create_certificate
			else
				Prompt "已取消操作..."
			fi
			;;
		14)
			cat <<EOF
为防止伪装站点千篇一律，特意准备了以下模板(更换模板后因清空了web文件夹订阅程序需要重新开启)
1. Speedtest-X
2. Mikutap
3. Flappy Winnie
4. FlappyFrog
5. bao
6. ninja
7. X Prober
8. 爱特文件管理器
EOF
			read -rp $'请选择 \e[95m1-8\e[0m: ' -n1 action
			is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 8 ] && {
				rm -rf $HOME_DIR/web
				case $action in
				1)
					git clone --depth 1 https://github.com/BadApple9/speedtest-x $HOME_DIR/web
					;;
				2)
					git clone --depth 1 https://github.com/HFIProgramming/mikutap $HOME_DIR/web
					;;
				3)
					git clone --depth 1 https://github.com/hahaxixi/hahaxixi.github.io $HOME_DIR/web
					;;
				4)
					git clone --depth 1 https://github.com/hahaxixi/FlappyFrog $HOME_DIR/web
					;;
				5)
					git clone --depth 1 https://github.com/hahaxixi/bao $HOME_DIR/web
					;;
				6)
					git clone --depth 1 https://github.com/hahaxixi/ninja $HOME_DIR/web
					;;
				7)
					mkdir -p $HOME_DIR/web && Wget_get_files $HOME_DIR/web/index.php https://github.com/kmvan/x-prober/raw/master/dist/prober.php
					;;
				8)
					git clone --depth 1 https://github.com/xiaoqidun/phpcp $HOME_DIR/web
					;;
				esac
				if [ -d $HOME_DIR/web ]; then
					chown -R nobody $HOME_DIR/web
				fi
			}
			;;
		15)
			cat <<EOF
为了Nginx服务器安全仅允许CDN的来源IP访问Nginx上架设的网页与反向代理。(目前仅支持Cloudflare)
1. 开启WAF防火墙 $([ -s $HOME_DIR/conf/cdn_only.conf ] && echo "(true)")
2. 关闭WAF防火墙
3. 启用iptables防护 $(iptables -w -t filter -C INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset >/dev/null 2>&1 && echo "(true)")
4. 取消iptables防护
EOF
			read -rp $'请选择 \e[95m1-4\e[0m: ' -n1 action
			is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 4 ] && {
				if [ ! -s /tmp/ips4 ] || [ ! -s /tmp/ips6 ]; then
					Wget_get_files /tmp/ips4 https://www.cloudflare.com/ips-v4
					Wget_get_files /tmp/ips6 https://www.cloudflare.com/ips-v6
				fi
				case $action in
				1)
					rm -f $HOME_DIR/conf/cdn_only.conf
					: <<EOF
if (\$http_cf_ipcountry = "") {
  return 403;
}
if (\$http_cf_connecting_ip = "") {
  return 403;
}
EOF
					echo -e "$(cat /tmp/ips4 /tmp/ips6)\n" | while IFS= read -r line; do
						[ "$line" ] && echo "allow   $line;" >>$HOME_DIR/conf/cdn_only.conf
					done
					echo "deny    all;" >>$HOME_DIR/conf/cdn_only.conf
					rm -f /tmp/ips4 /tmp/ips6
					Prompt "需要重启Nginx后生效"
					;;
				2)
					rm -f $HOME_DIR/conf/cdn_only.conf
					Prompt "需要重启Nginx后生效"
					;;
				3)
					ipset create cdn_only4 hash:net family inet
					ipset create cdn_only6 hash:net family inet6
					while IFS= read -r line || [ -n "$line" ]; do
						[ "$line" ] && ipset add cdn_only4 "$line"
					done </tmp/ips4
					while IFS= read -r line || [ -n "$line" ]; do
						[ "$line" ] && ipset add cdn_only6 "$line"
					done </tmp/ips6
					iptables -w -t filter -A INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset #禁止非CDN来源访问(tcp连接重置)
					ip6tables -w -t filter -A INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only6 src -j REJECT --reject-with tcp-reset
					Prompt "iptables规则添加完毕！"
					;;
				4)
					iptables -w -t filter -D INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset
					ip6tables -w -t filter -D INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only6 src -j REJECT --reject-with tcp-reset
					ipset destroy cdn_only4
					ipset destroy cdn_only6
					Prompt "iptables规则清理完成！"
					;;
				esac
			}
			;;
		16)
			if [[ $nginx_on != "--standalone" ]]; then
				Create_certificate
				cat <<EOF
需要客户端支持服务器订阅功能。(更新订阅程序需要关闭后再打开)
1. 开启订阅 $([ -s $HOME_DIR/web/subscriptions.php ] && echo "(true)")
2. 关闭订阅 $([ ! -s $HOME_DIR/web/subscriptions.php ] && echo "(true)")
EOF

				read -rp $'请选择 \e[95m1-2\e[0m: ' -n1 action
				is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 2 ] && {
					case $action in
					1)
						Wget_get_files $HOME_DIR/web/subscriptions.php $URL/src/subscriptions.php
						Prompt "你的订阅地址为 https://$tls_common_name/subscriptions.php"
						cat <<EOF
如果你的访问受到ISP干扰还可以使用以下地址进行加速访问
https://proxy.xzf.workers.dev/-----https://$tls_common_name/subscriptions.php
https://proxy.freecdn.workers.dev/?url=https://$tls_common_name/subscriptions.php

EOF
						;;
					2)
						rm -f $HOME_DIR/web/subscriptions.php
						;;
					esac
					Check_permissions
				}
			else
				Prompt "使用此功能需要先开启Nginx"
			fi
			;;
		17)
			cat <<EOF
部分插件无法同时监听IPv4和IPv6所以做了一个取舍，
使用前确保你的服务器支持选择的互联网协议版本！
(版本更新后会重置保存的记录)
  1. Auto $([ "$Protocol" = "auto" ] && echo "(true)")
  2. IPv4 $([ "$Protocol" = "ipv4" ] && echo "(true)")
  3. IPv6 $([ "$Protocol" = "ipv6" ] && echo "(true)")
EOF
			read -rp $'请选择 \e[95m1-3\e[0m: ' -n1 action
			is_number "$action" && [ "$action" -ge 1 ] && [ "$action" -le 3 ] && {
				case $action in
				1)
					Protocol=auto
					;;
				2)
					Protocol=ipv4
					;;
				3)
					Protocol=ipv6
					;;
				esac
				if [ "$action" ]; then
					sed -i "/^Protocol=/s/=.*/=$Protocol/" $HOME_DIR/conf/config.ini
					Prompt "请重启本脚本的所有服务以完成切换。"
				fi
			}
			;;
		*)
			break
			;;
		esac
		Press_any_key_to_continue
		clear
	done
}

Language() {
	cat <<EOF
  1. English (US)
  2. Chinese (PRC)
EOF
	if [ ${Language:=zh-CN} = 'en-US' ]; then
		read -rp $'请选择需要切换的语言 [\e[95m1-2\e[0m]:' -n1 un_select
	else
		read -rp $'Please enter a number [\e[95m1-2\e[0m]:' -n1 un_select
	fi
	echo
	case $un_select in
	1)
		Language="en-US"

		;;
	2)
		Language="zh-CN"
		;;
	esac
	if [ "$Language" ]; then
		sed -i "/^Language=/s/=.*/=$Language/" $HOME_DIR/conf/config.ini
	fi
}

Exit() {
	kill -9 $NOW_PID
}

if [ "$1" = "daemon" ]; then
	Daemon
elif [ "$1" = "start" ]; then
	Start
elif [ "$1" = "restart" ]; then
	Stop
	Start
elif [ "$1" = "stop" ]; then
	Stop
else
	first=0
	while true; do
		((first++))
		[ "$first" -le 1 ] && Check
		clear
		Author
		Status
		if [ ${Language:=zh-CN} = 'en-US' ]; then
			cat <<EOF
  1. User Management->>
  2. Turn on service 
  3. Close service
  4. Uninstallation
  5. Upgrade
  6. 更换语言
  7. Advanced Features->>
EOF
			read -rp $'Please enter a number [\e[95m1-7\e[0m]:' -n1 action
			mr="Default"
		else
			cat <<EOF
  1. 用户列表->>
  2. 启动运行
  3. 停止运行
  4. 卸载删除
  5. 版本更新
  6. Language
  7. 高级功能->>
EOF
			read -rp $'请选择 [\e[95m1-7\e[0m]: ' -n1 action
		fi
		echo
		case $action in
		1)
			User_list_display
			;;
		2)
			Start
			;;
		3)
			Stop
			;;
		4)
			Uninstall
			;;
		5)
			Update_core
			;;
		6)
			Language
			;;
		7)
			Advanced_features
			;;
		*)
			break
			;;
		esac
	done
fi
