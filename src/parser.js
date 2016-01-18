/**
 * SAE LogParser
 * parser.js
 */
var output = [],
	osInfo = [];

exports.segment = function (str) {
	//SAE日志正则表达式模板
	var template = /(\w+\.\w+\.\w+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)\s+(\d+)\s+\[(\d{2}\/\w{3}\/\d{4}\:\d{2}\:\d{2}\:\d{2}\s+\+\d{4})\]\s+(\w+)\s+(\d+)\s+(\d+)\s+\"([^"]*)\"\s+(\d+)\s+([^\s]+)\s+\"([^"]*)\"\s+\"([^"]*)\"\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d+)\s+(\w+)/gim;
	parseArr = new Array();
	parseArr = template.exec(str);
	if (parseArr != null) {
		parseArr[9] = parseArr[9].split(" ");//分割header部分
		output = {
			"domain" : parseArr[1],
			"origin" : parseArr[2],
			"requestTime" : parseArr[5],
			"appName" : parseArr[6],
			"header" : {
				"method" : parseArr[9][0],
				"statusCode" : parseArr[10],
				"path" : parseArr[9][1],
				"httpInfo" : parseArr[9][2]
			},
			"url" : parseArr[12],
			"userAgent" : parseArr[13]
		}
		return output;
	} else {
		return false;
	}
}

//分析UserAgent
exports.uaParser = function (useragent) {
	var os = {
		"Android" : /(Android)\s+(\d+\.\d+\.*\d*)/gim,
		"iOS" : /(iPhone OS)\s+(\d+\_\d+\_*\d*)/gim,
		"Windows" : /(Windows NT)\s+(\d+\.\d+\.*\d*)/gim
	};
	var count = 0, idx = 0, tindex;

	wechatReg = /MicroMessenger\/(\d+\.\d+\.*\d*\.*\w*\.*\d*)/gim;

	netTypeReg = /NetType\/([^\s]*)/gim;

	if (/Android/.test(useragent)) {
		osInfo = os.Android.exec(useragent);
		if (/MicroMessenger/.test(useragent)) {
			wechatInfo = (wechatReg.exec(useragent))[1];
		} else {
			wechatInfo = 'unknown';
		}
		if (/NetType/.test(useragent)) {
			netType = (netTypeReg.exec(useragent))[1];
		} else {
			netType = 'unknown';
		}
		while (count != 4)
		{
			idx = useragent.indexOf('; ');
			useragent = useragent.substring(idx + 1);
			count++;
		}
		cellphone = (/([^)]+)/gi.exec(useragent))[1].substring(1);
	} else if (/iPhone OS/.test(useragent)) {
		osInfo = os.iOS.exec(useragent);
		osInfo[2] = osInfo[2].replace(/_/g, ".");
		if (/MicroMessenger/.test(useragent)) {
			wechatInfo = (wechatReg.exec(useragent))[1];
		} else {
			wechatInfo = 'unknown';
		}
		if (/NetType/.test(useragent)) {
			netType = (netTypeReg.exec(useragent))[1];
		} else {
			netType = 'unknown';
		}
		cellphone = 'unknown';
	} else if (/Windows NT/.test(useragent)) {
		osInfo = os.Windows.exec(useragent);
		wechatInfo = 'unknown';
		netType = 'unknown';
		cellphone = 'unknown';
	} else {
		osInfo = ['unknown', 'unknown', 'unknown'];
		wechatInfo = 'unknown';
		netType = 'unknown';
		cellphone = 'unknown';
	}

	if (osInfo == null || osInfo.length <= 1) {
		output = {
			"system" : "unknown",
			"version" : "unknown",
			"wechatVersion" : wechatInfo,
			"netType" : netType,
			"cellphone" : cellphone
		}
	} else {
		output = {
			"system" : osInfo[1],
			"version" : osInfo[2],
			"wechatVersion" : wechatInfo,
			"netType" : netType,
			"cellphone" : cellphone
		}
	}

	return output;
}