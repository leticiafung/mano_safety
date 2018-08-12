/**
 * Created by leticia on 2018/6/27.
 */
//增加安全对象，destination : 保护主体的对象,ip的类型判断还没有进行
//要写入的json对象
function  InputObj (){
    this.operation = 'create';
    this.init = function (sfcNum){
        this.name = 'sfc'+ sfcNum;
        this.VNF = [];
        this.constrain = [];
        this.QoS = {};
        this.objective = 'cpu';
        this.destination = '';
    };
    let flavor = {};//json parse会输出吗？?

    this.setflavor = function(instream){
        //入口流量
        //instream = Number(instream);
        if(instream < 100){
            flavor.cpu = 1;
            flavor.memory = 1000;
            flavor.disk = 10;
        }
        else if(instream > 100 && instream < 1000){
            flavor.cpu = 1;
            flavor.memory = 1500;
            flavor.disk = 15;

        }
        else{
            flavor.cpu = 2;
            flavor.memory = 2000;
            flavor.disk = 20;
        }
    };
    this.getFlavor = function (){
        return flavor;
    }
}
InputObj.prototype.parseIntent = function(intent,hostmap){
    if(intent === ''){
        this.erralert('empty');
        return;
    }
    intent = intent.toLowerCase();
    let intents = intent.trim().split('and');
    for(let i = 0 ,len = intents.length; i < len ; i++){
        words = intents[i].split(' ');
        if(words.length <= 1){
            this.erralert('err');
            this.clearObj();
        }
        //handle fw/IPS
        if(words[0] === 'allow' || words[0] === 'reject'){
            this.allowAndreject(words,hostmap);
        }
        else if(words[0] === 'detect'){
            this.detect(words,hostmap);
        }
        else if(words[0] === 'monitor'){
            this.monitor(words,hostmap);
        }
        else{
            this.erralert('err');
            this.clearObj();
        }

    }
};

InputObj.prototype.erralert = function(key){
    if(key === 'empty'){
        alert('输入不能为空！');
    }
    else if(key === 'err'){
        alert('输入出错！');
    }
    else if(key === 'terr'){
        alert('时间格式不对！');
    }
};
//handle allow and reject FW or DPI .，加destip才可以了
InputObj.prototype.allowAndreject = function(arr,hostmap){
    let len = arr.length,//arr = ['allow','service:http&ip:....','time:week{1,2,3}&clock{01:00-02:22}']
        serviceTag = 0,
        fullrule = 'iptables -A FORWARD ',
        tempr = '';//一条rule
    let mode  = '';//一个mode
    ruleTypes = arr[1].split('&');
    for(let j = 0 ,rlen = ruleTypes.length ; j < rlen ; j++){
        let arule = ruleTypes[j].split(':');
        if(arule[0] === 'service'){
            //service handle,service type
            if(arule[1] === 'http'){
                tempr += '-p tcp --dport 80 ';
            }
            else if(arule[1] === 'dns'){
                tempr += '-p udp --dport 53 ';
            }
            else if(arule[1] === 'ssh'){
                tempr +=  '-p tcp --dport 22 ';
            }
            else if(arule[1] === 'ftp'){
                tempr +=  '-p tcp --dport 21 ';
            }
            else{//其他服务还未知 no limit
                tempr += '';
            }
            serviceTag = 1;
        }
        else if(arule[0] === 'ip'){
            //TODO ip合法性验证
            tempr += '-s'+ arule[1] + ' ';
        }
        else if(arule[0] === 'protocol'){
            let protocols = ['tcp' ,'udp','icmp'];
            if(protocols.indexOf(arule[1]) !== -1){
                if(serviceTag === 0 ) {
                    tempr += '-p' + arule[1] + ' ';
                }
                //对协议类型没有判断
            }
            else{
                this.erralert('err');
                this.clearObj();
                return;
            }
        }
        else if(arule[0] === 'dport'){
            if(serviceTag === 0) {
                if(parseInt(arule[1]) >= 0 && parseInt(arule[1]) <= 65535 )
                    tempr += '--dport ' + parseInt(arule[1]) + ' ';
            }
        }
        else if(arule[0] === 'sport'){
            if(serviceTag === 0) {
                if(parseInt(arule[1]) >= 0 && parseInt(arule[1]) <= 65535 )
                    tempr += '--sport ' + parseInt(arule[1]) + ' ';
            }
        }
        else if(arule[0] === 'local'){//当前网络下的host对应的IP [{id:xxx,ip:xxxxx,name:xxxx}]把name,ip取出来用map 存着
            if(hostmap.get(arule[1]))
                tempr += '-s ' + hostmap.get(arule[1]);

        }
        else{
            this.erralert('err');
            this.clearObj();
            return ;
        }

    }
    if(len >= 3){
        let times = arr[2].split('&');//['week:1,2,3','clock:22:00-23:00']
        for(let k = 0 ; k < times.length ;k ++){
            let atimes = times[k].split(':');
            if(atimes[0] === 'week') {
                let weekdays = atimes[1].split(',');
                if (weekdays.every((item) => {
                        return (parseInt(item) > 0 && parseInt(item) < 8);
                    }) === true)
                    mode += '-m time --weekdays ' + atimes[1] + ' ';
                else{
                    this.erralert('terr');
                    this.clearObj();
                    return;
                }
            }
            else if(atimes[0] === 'clock'){
                let clocks = atimes[1].split('-');
                if(clocks.length < 2){
                    this.erralert('err');
                    this.clearObj();
                    return;

                }
                //时间格式为00:00，目前没有对格式多样化。
                clocksnum1 = clocks[0].slice(0,2) + clocks[0].slice(3);
                clocksnum2 = clocks[1].slice(0,2) + clocks[1].slice(3);
                if(Number(clocksnum1) > Number(clocksnum2) || Number(clocksnum1) > 2359 || Number(clocksnum1) < 0 || Number(clocksnum2) > 2359 || Number(clocksnum2) < 0){
                    this.erralert('terr');
                    this.clearObj();
                    return;
                }
                mode += '-m time --timestart ' + clocks[0] + '--timestop ' + clocks[1] + ' ';
            }
        }

    }
    let tail = '-j ';// 最后的accept或者reject处理
    let action = 'ACCEPT';
    if(arr[0] === 'allow'){
        tail += 'ACCEPT ';

    }
    else if(arr[0] === 'reject'){
        tail += 'REJECT ';
        action = 'REJECT';
    }
    else{
        this.erralert('terr');
        this.clearObj();
        return;
    }
    //是否已有服务功能，目前的DPI的相关特征没有考虑，以后增加的话要增加类型的flag,对于防火墙，设定allow/reject各自合并
    let pos = this.findVnf('FW_image',action);
    let r = fullrule + tempr + mode + tail + ';';//最终的一条规则
    if(pos !== -1){
        this.VNF[pos].rule += r;
    }
    else{
        let vnf = {};
        let date = new Date();
        vnf.name = date.getTime();
        vnf.type = 'FW_image';
        vnf.flavor = this.getFlavor();
        vnf.rule = r ;
        this.VNF.push(vnf);
    }

};
//find vnf type return -1 means not exist ,return the very vnf
InputObj.prototype.findVnf = function(vnfType,fwact){
    for(let m = 0 ,vnflen = this.VNF.length;m < vnflen ; m++ ){
        if(this.VNF[m].type === vnfType){
            if(arguments.length > 1 ){
                let rega = /ACCEPT/g ;
                let regd = /REJECT/g ;
                if(rega.test(this.VNF[m].rule) && fwact === 'ACCEPT' || regd.test(this.VNF[m].rule) && fwact === 'REJECT'){
                        return m;
                }
            }
            return m;
        }
    }
    return -1;
};
InputObj.prototype.clearObj = function(){
    this.VNF = [];
    this.constrain = [];
    this.QoS = {};
};

// InputObj.prototype.getFlavor = function getFlavor(){
//     //TODO
//     return {
//         cpu: 1,
//         memory: 1000,
//         disk: 10
//     }
// };
//IDS 输入顺序必须调整为协议，端口，目的端口
InputObj.prototype.detect = function (arr,hostmap) {//['detect','attack:tcpscan&sport:30&ip:111&protocol:222'],protocol有
    let protocols = ['tcp' ,'udp','icmp'],
        hasattack = 0;//是否使用attack
    let attacktypes = arr[1].split('&');
    let idsrule = '';
    //重新编order,按照[service,协议，ip,sport,dport]//协议必须有
    let relorder  = ['','','any','any','any'];
    for(let j = 0 ,alen = attacktypes.length; j < alen ; j++){
        let sattack = attacktypes[j].split(':');
        if(sattack[0] === 'attack'){
            //attack function handle
            if(handleattack(sattack[1])!== ''){
                idsrule = handleattack(sattack[1]);
            }
            else{
                this.erralert('terr');
                this.clearObj();
                return ;

            }
        }
        else if(sattack[0] === 'ip' || sattack[0] === 'local'){
            //TODO IP DETECT
            if(sttack[0] === 'local'){//当前网络下的host对应的IP [{id:xxx,ip:xxxxx,name:xxxx}]把name,ip取出来用map 存着
                if(hostmap.get(sattack[1]))
                    relorder[2] = hostmap.get(sattack[1]);
            }
            else
                relorder[2] = sattack[1];
        }
        else if(sattack[0] === 'protocol'){
            let protocols = ['tcp' ,'udp','icmp'];
            if(protocols.indexOf(sattack[1]) !== -1)
                 relorder[1] = sattack[1];
        }
        else if(sattack[0] === 'sport'){
            if(parseInt(sattack[1]) >= 0 && parseInt(sattack[1]) <= 65535 ){
                reload[3] = sattack[1];
            }
        }
        else if(sattack[0] === 'dport'){
            if(parseInt(sattack[1]) >= 0 && parseInt(sattack[1]) <= 65535 ){
                reload[4] = sattack[1];
            }
        }
        else{
            this.erralert('err');
            this.clearObj();
            return;

        }
    }
    if(relorder[1] === '' ){
        this.erralert('err');
        this.clearObj();
        return ;
    }
    if(relorder[0] === ''){
        idsrule += 'alert ' + relorder[1] + ' '+ relorder[2] + ' ' +  relorder[3] + ' -> '+ this.destination + relorder[4] + ' (msg:"user instrution detect ' + this.destination + '";); ' ;
    }
    else{
        this.erralert('terr');
        this.clearObj();
        return ;
    }
    function handleattack(myattack){//:后的内容
        let highattck = ['tcpscan','synflood','pingscan','xmasscan'];
        //let myattacks = myattack.split(':');
        let irule = '';
        if(highattck.indexOf(myattack) !== -1){
            if(myattack === 'synflood')
                irule += 'alert tcp  any -> ' +  this.destination + ' 22 (flags: S; msg:"Possible TCP DoS"; flow: stateless;threshold: type both, track by_src, count 70, seconds 10; sid:10001;rev:1;) ';
            else if(myattack === 'tcpscan')
                irule += 'alert tcp any any -> '+ this.destination + ' 22 (msg: "NMAP TCP Scan"; sid:10000005; rev:2; ) ';
            else if(myattack === 'pingscan')
                irule += 'alert icmp any any -> '+ this.destination + ' any (msg: "NMAP ping sweep Scan "; dsize:0;sid:10000004; rev:1;) ';
            else
                irule += 'alert tcp any any -> ' + this.destination + ' 22 (msg:"Nmap XMAS Tree Scan"; flags:FPU; sid:1000006; rev:1;) '
        }
        else{

            return '';
        }
        return irule;

    }
    let pos = this.findVnf('IDS_image');
    if(pos !== -1){
        this.VNF[pos].rule += idsrule;
    }
    else{
        let vnf = {};
        let date = new Date();
        vnf.name = date.getTime();
        vnf.type = 'IDS_image';
        vnf.flavor = this.getFlavor();
        vnf.rule = idsrule ;
        this.VNF.push(vnf);
    }
};  //snort规则不支持时间变化的要求。

//TODO IPS
InputObj.prototype.monitor = function (arr) {

};

//let hostmap = new Map();通过参数传递进去

//使用正则匹配会更好吧！！

//页面逻辑处理