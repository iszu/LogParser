# LogParser
A Log Parser by NodeJS For SAE

###如何使用
```javascript
var logparser = require("parser.js");
logParsed = logparser.segment(logSource);
logparser.uaParser(logParsed.userAgent);
```

#####注意
此Node模块仅适配了SAE的日志。