import * as ejs from 'ejs';
import path from 'path';
import fsp from 'fs/promises';

const STATIC_DIR = 'static';

async function getFiles() {
    const files = {
        files: {}
    };

    const fileList = await fsp.readdir(STATIC_DIR, {
        withFileTypes: true
    });

    const readPromises = fileList.filter(f => f.isFile()).map(async f => {
        files.files[f.name] = await fsp.readFile(path.join(STATIC_DIR, f.name), { encoding: 'utf-8' });
        console.log(`inserting ${f.name}`);
    });
    await Promise.all(readPromises);
    return files;
}

ejs.renderFile('plugin-template.go', await getFiles(), {}, async (err, str) => {
    if (err) {
        console.error(err);
        return;
    }
    fsp.writeFile('../honeypot-middleware.go', str);
});
