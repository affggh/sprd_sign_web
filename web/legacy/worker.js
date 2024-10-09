// worker.js

importScripts(
    "./sprd_sign.js", // sprd_sign
    "./imgheaderinsert.js", // imageheaderinsert
    "./get-raw-image.js", // get_raw_image
);
// 监听主线程发送的消息
self.addEventListener('message', async (event) => {
    const { file, id } = event.data;

    function postRunMessage(msg) {
        self.postMessage({id, type: 'log', message: msg});
    }
  
    try {
      // 发送处理开始的消息
      self.postMessage({ id, type: 'log', message: `开始处理文件: ${file.name}` });
      postRunMessage("Script by affggh...");
  
      sprd_sign({
        noInitialRun: true,
        print: postRunMessage,
        printErr: postRunMessage,
      }).then((mod1) => {
        const fileReader = new FileReader()

        fileReader.onload = function (event) {
            const data = new Uint8Array(event.target.result);
            mod1.FS.writeFile('/home/web_user/boot.img', data);
            mod1.FS.chdir('/home/web_user');
            self.postMessage({id, type: 'log', message: `将boot.img 放入 /home/web_user/boot.img`});

            get_raw_image({
                noInitialRun: true,
                print: postRunMessage,
                printErr: postRunMessage,
            }).then((mod2) => {
                mod2.FS.mount(mod2.PROXYFS, {
                    root: "/home/web_user",
                    fs: mod1.FS
                }, "/home/web_user");

                mod2.FS.chdir('/home/web_user');
                mod2.callMain(["boot.img"]);

                imgheaderinsert({
                    noInitialRun: true,
                    print: postRunMessage,
                    printErr: postRunMessage,
                }).then((mod3) => {
                    mod3.FS.mount(mod2.PROXYFS, {
                        root: "/home/web_user",
                        fs: mod1.FS
                    }, "/home/web_user");
    
                    mod3.FS.chdir('/home/web_user');

                    mod3.callMain(["boot.img", "0"]);

                    try {
                        mod1.FS.stat('/home/web_user/boot-sign.img');
                    } catch (error) {
                        postRunMessage("Could not fetch boot-sign.img");
                        return;
                    }

                    mod1.callMain(["boot-sign.img", "/resource"]);

                    const signed_data = mod1.FS.readFile("/home/web_user/boot-sign.img");
                    const blob = new Blob([signed_data], { type: file.type });
                    const processedUrl = URL.createObjectURL(blob);

                    self.postMessage({ id, type: 'complete', processedUrl, processedFileName: `${file.name}` });
                    self.postMessage({ id, type: 'log', message: `文件 ${file.name} 处理完成。` });
                });

            });
        };

        fileReader.readAsArrayBuffer(file);
      });
      // 模拟处理：将内容转换为大写
      //const processedContent = fileContent.toUpperCase();
  
      // 创建处理后的文件
      //const processedBlob = new Blob([processedContent], { type: file.type });
      //const processedUrl = URL.createObjectURL(processedBlob);
  
      // 发送处理完成的消息
      //self.postMessage({ id, type: 'complete', processedUrl, processedFileName: `processed_${file.name}` });
  
      // 发送处理完成的日志
      //self.postMessage({ id, type: 'log', message: `文件 ${file.name} 处理完成。` });
    } catch (error) {
      // 发送错误日志
      self.postMessage({ id, type: 'log', message: `处理文件 ${file.name} 时出错: ${error.message}` });
    }
  });
  