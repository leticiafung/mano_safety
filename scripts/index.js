/**
 * Created by leticia on 2018/6/27.
 */
//let hostmap = new Map();//数据应该是不可调用的,什么时候清除？
$(window).ready(()=>{
    //
    // $.ajax({
    //     type:'get',
    //     url:'/host_list',
    //     success:function(data){
    //         console.log(data);//[{},{},{}]
    //         //使用文档碎片
    //         let frag = document.createDocumentFragment();
    //         $.each(data, function(i, item) {
    //             let  newOption = '<option value=' + item.ip + '>'+ item.name + '</option>';
    //             hostmap.set(item.name ,item.ip);
    //             frag.appendChild(newOption);
    //         });
    //         $("select[name = 'host']").appendChild(frag);
    //
    //     },
    //     error:function(){
    //         alert('读取失败！');
    //     }
    // });
    //==========================================================
    //for test
    let hostmap = new Map([['host1','192.168.2.1'],['host2','1.1.1.10']]);
    let frag = document.createDocumentFragment();
    let newOption = "<option value='1.1.1.10'>host2</option>";
    frag.appendChild(newOption);
    $("select[name = 'host']").appendChild(frag);

    //=========================================================
    $('#update_host').click(()=>{
        $("select[name = 'host']").html('<option selected="selected" value="none">主机名</option>');
        $.ajax({
            type:'get',
            url:'/host_list',
            success:function(data){//传过来的格式是什么？？？
                console.log(data);//[{},{},{}]
                //使用文档碎片
                let frag = document.createDocumentFragment();
                $.each(data, function(i, item) {
                    let  newOption = '<option value=' + item.ip + '>'+ item.name + '</option>';
                    hostmap.set(item.name ,item.ip);
                    frag.appendChild(newOption); //TODO
                });
                $("select[name = 'host']").appendChild(frag);
            },
            error:function(){
                alert('读取失败！');
            }
        });
    });
    let sfcNum = 0;
    let inobj = new InputObj(sfcNum);
    inobj.init();
    sfcNum++;
    $('#createsfc').click(()=>{
        if($(select[name = 'host']).val() === 'none'){
            alert('请输入安全需求主体！');
        }
        else{
            inobj.destination = $(select[name = 'host']).val();
            let instream  = $('#instream').val() || 100;
            inobj.setflavor();
            if($(select[name = 'perform']).val() !== 'none' ){
                inobj.objective = $(select[name = 'perform']).val();
            }
            let myintent = $('#intent').val();
            inobj.parseIntent(myintent);
            console.dir(inobj);
            // if(inobj.VNF !== [] && inobj.destination !== ''){
            //     let sendData = JSON.stringify(inobj);
            //     $.ajax({
            //         type:'post',
            //         url: '/template',
            //         data:sendData,
            //         success:function(data){
            //             console.log(data);
            //             alert(data);
            //         },
            //         error:function(){
            //             alert('读取失败！');
            //         }
            //     });
            // }
        }
    });
});




