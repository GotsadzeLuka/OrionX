const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {resolve}=require('node:path');
const Module=require('node:module');
const {transformSync}=require('esbuild');

const path=resolve(__dirname,'../src/lib/passport.ts');
const js=transformSync(readFileSync(path,'utf8'),{loader:'ts',format:'cjs'}).code;
const mod=new Module(path,module);mod.filename=path;mod.paths=Module._nodeModulePaths(resolve(__dirname,'../src/lib'));
mod._compile(js,path);
const {isIssuedPassport}=mod.exports;

test('a finalized demo passport is still issued and accessible when institutional trust is unconfirmed',()=>{
 assert.equal(isIssuedPassport({official:false,passportId:'ORX-123',latest:{version:1}}),true);
 assert.equal(isIssuedPassport({official:true,passportId:'ORX-123',latest:{version:1}}),true);
});
test('a reserved passport or empty workspace is not issued',()=>{
 assert.equal(isIssuedPassport({official:false,passportId:null,latest:null}),false);
 assert.equal(isIssuedPassport({official:false,passportId:'reserved',latest:null}),false);
 assert.equal(isIssuedPassport(null),false);
});
test('UI gates do not confuse institutional attestation with issuance',()=>{
 const passportPage=readFileSync(resolve(__dirname,'../src/app/passport/page.tsx'),'utf8');
 const dashboard=readFileSync(resolve(__dirname,'../src/app/dashboard/page.tsx'),'utf8');
 assert.match(passportPage,/isIssuedPassport\(passport.data\)/);
 assert.match(dashboard,/isIssuedPassport\(p\)/);
 assert.doesNotMatch(passportPage,/passport.data\?\.official/);
 assert.doesNotMatch(dashboard,/p\.official/);
});
