# Struts2Burp
一款检测Struts2 RCE漏洞的burp被动扫描插件，仅检测url后缀为`.do`以及`.action`的数据包

**本项目旨在学习以及自我项目检测，请勿用于非法用途！**
# 使用
```
git clone https://github.com/x1a0t/Struts2Burp
cd Struts2Burp
mvn clean package -DskipTests
```
将目录`target`下生成的jar包导入burp即可
# 检测范围
* Devmode
* S2-001
* S2-003/S2-005
* S2-007
* S2-009
* S2-012
* S2-013/S2-014
* S2-015
* S2-016
* S2-032
* S2-045
* S2-046
* S2-057
* S2-059
* S2-061
* ...