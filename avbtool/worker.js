// worker.js

importScripts("https://cdn.jsdelivr.net/pyodide/v0.26.2/full/pyodide.js");

async function loadPyodideAndPackages() {
    self.pyodide = await loadPyodide();
    await self.pyodide.loadPackage(["hashlib", "pycryptodome"]);
}
let pyodideReadyPromise = loadPyodideAndPackages();

function readFileAsUint8Array(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = (event) => {
            const buffer = new Uint8Array(event.target.result);
            resolve({ name: file.name, content: buffer });
        };

        reader.onerror = (event) => {
            reject({ name: file.name, error: event.target.error });
        };

        reader.readAsArrayBuffer(file); // 你可以根据需要选择 readAsArrayBuffer, readAsDataURL 等
    });
}

self.onmessage = async (event) => {

    function printMsg(msg) {
        postMessage({
            id, type: "log", message: msg
        });
    }

    // make sure loading is done
    await pyodideReadyPromise;
    const { id, boot_image, vbmeta_image, type, partition_size, android_ver } = event.data;
    // Now is the easy part, the one that is similar to working in the main thread:

    // 重定向标准输出
    pyodide.setStdout({
        batched: (texts) => printMsg(texts),
    });

    // 重定向错误输出
    pyodide.setStderr({
        batched: (texts) => printMsg(texts),
    });


    try {
        const module_file = ['./avbtool.py', './generate_sign_script_for_vbmeta.py', './sign_image.py'];
        const resource_file = ['./rsa4096_custom_pub.bin', './rsa4096_vbmeta.pem']
        const all_file = module_file.concat(resource_file);
        const web_workdir = "/home/web_user/"

        //printMsg("Loading pyodide environment...")
        //await self.pyodide.loadPackagesFromImports(['hashlib']);
        //let results = await self.pyodide.runPythonAsync(python);

        const file_fetch_promise = all_file.map(file => fetch(file).then(
            response => {
                if (!response.ok) {
                    throw new Error("Could not open file" + file);
                }
                return response.arrayBuffer();
            }
        ));

        Promise.all(file_fetch_promise).then(
            async arrayBuffer => {
                printMsg("加载脚本文件...");
                arrayBuffer.forEach(
                    (buffer, index) => {
                        const byteBuffer = new Uint8Array(buffer);
                        self.pyodide.FS.writeFile(all_file[index], byteBuffer);
                        printMsg("Write file:" + all_file[index]);
                    }
                );

                //self.pyodide.FS.chdir(web_workdir);
                // Read vbmeta and boot into workdir
                printMsg("将boot和vbmeta写入到虚拟文件系统...");
                const boot_data = await readFileAsUint8Array(boot_image);
                const vbmeta_data = await readFileAsUint8Array(vbmeta_image);
                self.pyodide.FS.writeFile("boot.img", boot_data.content);
                self.pyodide.FS.writeFile("vbmeta.img", vbmeta_data.content);

                printMsg("签名镜像...");
                let sign_img = self.pyodide.pyimport("sign_image");
                sign_img.sign_image("vbmeta.img", type, Number(android_ver), "boot.img", partition_size);
                printMsg("打包已签名的镜像...");
                sign_img.pack_zip();

                const signed_archive = self.pyodide.FS.readFile("SignedImages.zip");
                const blob = new Blob([signed_archive], { type: 'application/octet-stream' });
                const signed_zip = URL.createObjectURL(blob);

                self.postMessage({ id, type: "success", signed_zip });
            }
        ).catch(error => {
            printMsg("Error while loading" + error);
            console.error("Error: ", error);
        });
    } catch (error) {
        self.postMessage({ id, type: "log", message: error });
    }
};