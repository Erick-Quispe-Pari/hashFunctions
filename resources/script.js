var botonHashMd4 = document.getElementById("hashMd4");
var botonHashMd5 = document.getElementById("hashMd5");
var botonHashSha1 = document.getElementById("hashSha1");
var botonHashSha256 = document.getElementById("hashSha256");
var botonHashHmac1 = document.getElementById("hashHmac1");
var botonHashHmac256 = document.getElementById("hashHmac256");

var lengthResult = document.getElementById("lengthResult");
var textInput = document.getElementById("text_input");
var textResult = document.getElementById("text_result");


//ASIGNACION DE MD4
botonHashMd4.onclick = function(){
    let finalArr = md4(textInput.value);
    let finalText = "";
    for(let i=0;i<finalArr.length;i++){
        preFixedText=parseInt(finalArr[i],2).toString(16);
        finalText += addPadding(preFixedText,8,"0");
    }
    textResult.innerHTML = finalText;
    lengthResult.innerHTML = finalText.length+" caracteres";
}


//ASIGNACION DE MD5
botonHashMd5.onclick = function(){
    let finalArr = md5(textInput.value);
    let finalText = "";
    for(let i=0;i<finalArr.length;i++){
        preFixedText=parseInt(finalArr[i],2).toString(16);
        finalText += addPadding(preFixedText,8,"0");
    }
    textResult.innerHTML = finalText;
    lengthResult.innerHTML = finalText.length+" caracteres";
}


//ASIGNACION DE SHA1
botonHashSha1.onclick = function(){
    let finalArr = sha1(textInput.value);
    let finalText = "";
    for(let i=0;i<finalArr.length;i++){
        preFixedText=parseInt(finalArr[i],2).toString(16);
        finalText += addPadding(preFixedText,8,"0");
    }
    textResult.innerHTML = finalText;
    lengthResult.innerHTML = finalText.length+" caracteres";
}


//ASIGNACION DE SHA256
botonHashSha256.onclick = function(){
    let finalArr = sha256(textInput.value);
    let finalText = "";
    for(let i=0;i<finalArr.length;i++){
        preFixedText=parseInt(finalArr[i],2).toString(16);
        finalText += addPadding(preFixedText,8,"0");
    }
    textResult.innerHTML = finalText;
    lengthResult.innerHTML = finalText.length+" caracteres";
}


//ASIGNACIONES DE HMAC
botonHashHmac1.onclick = function(){
    let secret = "0001010101110101010010";
    let finalArr = hmac(textInput.value,secret,true);
    let finalText = "";
    for(let i=0;i<finalArr.length;i++){
        preFixedText=parseInt(finalArr[i],2).toString(16);
        finalText += addPadding(preFixedText,8,"0");
    }
    textResult.innerHTML = finalText;
    lengthResult.innerHTML = finalText.length+" caracteres";
}


botonHashHmac256.onclick = function(){
    let secret = "0001010101110101010010";
    let finalArr = hmac(textInput.value,secret,false);
    let finalText = "";
    for(let i=0;i<finalArr.length;i++){
        preFixedText=parseInt(finalArr[i],2).toString(16);
        finalText += addPadding(preFixedText,8,"0");
    }
    textResult.innerHTML = finalText;
    lengthResult.innerHTML = finalText.length+" caracteres";
}


//FUNCION HASH MD4
function md4(text){
    let arrWord = init(text,true);
    let storedValues = [];
    storedValues[0]="01100111010001010010001100000001";
    storedValues[1]="11101111110011011010101110001001";
    storedValues[2]="10011000101110101101110011111110";
    storedValues[3]="00010000001100100101010001110110";
    let arrAux=[];
    arrAux[0]=arrWord[1];
    arrAux[1]=arrWord[2];
    arrAux[2]=arrWord[3];
    arrAux[3]=arrWord[4];
    for(let i=0;i<arrWord.length;i+=16){
        let rotations=[];
        let key=0;
        let indices=[];
        //Primeras 16 rondas
        rotations = [3,7,11,19];
        key=0;
        key=addPadding(key.toString(2),32,"0");
        for(let j=0;j<16;j++){  
            let aux = bXor(arrAux[0],md4Function1(arrAux));
            aux = bXor(aux,arrWord[i+j]);
            aux = bXor(aux,key);
            aux = bLeftRotation(aux,rotations[j%4]);
            arrAux[2]=arrAux[1];
            arrAux[3]=arrAux[2];
            arrAux[0]=arrAux[3];
            arrAux[1]=aux;
        }
        //Segundas 16 rondas
        rotations = [3,5,9,13];
        indices = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15];
        key="01011010100000100111100110011001";
        for(j=0;j<16;j++){  
            let aux = bXor(arrAux[0],md4Function2(arrAux));
            aux = bXor(aux,arrWord[i+indices[j]]);
            aux = bXor(aux,key);
            aux = bLeftRotation(aux,rotations[j%4]);
            arrAux[2]=arrAux[1];
            arrAux[3]=arrAux[2];
            arrAux[0]=arrAux[3];
            arrAux[1]=aux;
        }
         //Terceras 16 rondas
         rotations = [3,9,11,15];
         indices = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15];
         key="01101110110110011110101110100001";
         for(let j=0;j<16;j++){  
             let aux = bXor(arrAux[0],md4Function3(arrAux));
             aux = bXor(aux,arrWord[i+indices[j]]);
             aux = bXor(aux,key);
             aux = bLeftRotation(aux,rotations[j%4]);
             arrAux[2]=arrAux[1];
             arrAux[3]=arrAux[2];
             arrAux[0]=arrAux[3];
             arrAux[1]=aux;
         }
         storedValues[0]=bXor(arrAux[0],storedValues[0]);
         storedValues[1]=bXor(arrAux[1],storedValues[1]);
         storedValues[2]=bXor(arrAux[2],storedValues[2]);
         storedValues[3]=bXor(arrAux[3],storedValues[3]);
    }
    return arrAux;
}


//FUNCION HASH MD5
function md5(text){
    let arrWord = init(text,true);
    let storedValues = [];
    storedValues[0]="01100111010001010010001100000001";
    storedValues[1]="11101111110011011010101110001001";
    storedValues[2]="10011000101110101101110011111110";
    storedValues[3]="00010000001100100101010001110110";
    let arrAux=[];
    arrAux[0]=arrWord[1];
    arrAux[1]=arrWord[2];
    arrAux[2]=arrWord[3];
    arrAux[3]=arrWord[4];
    for(let i=0;i<arrWord.length;i+=16){
        let rotations=[];
        let key=0;
        let indices=[];
        //Primeras 16 rondas
        rotations = [7,12,17,22];
        key=0;
        key=addPadding(key.toString(2),32,"0");
        for(let j=0;j<16;j++){  
            let aux = bXor(arrAux[0],md5Function1(arrAux));
            aux = bXor(aux,arrWord[i+j]);
            aux = bXor(aux,key);
            aux = bLeftRotation(aux,rotations[j%4]);
            aux = bXor(aux,arrAux[1]);
            arrAux[2]=arrAux[1];
            arrAux[3]=arrAux[2];
            arrAux[0]=arrAux[3];
            arrAux[1]=aux;
        }
        //Segundas 16 rondas
        rotations = [5,9,14,20];
        indices = [1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12];
        key="01011010100000100111100110011001";
        for(j=0;j<16;j++){  
            let aux = bXor(arrAux[0],md5Function2(arrAux));
            aux = bXor(aux,arrWord[i+indices[j]]);
            aux = bXor(aux,key);
            aux = bLeftRotation(aux,rotations[j%4]);
            aux = bXor(aux,arrAux[1]);
            arrAux[2]=arrAux[1];
            arrAux[3]=arrAux[2];
            arrAux[0]=arrAux[3];
            arrAux[1]=aux;
        }
         //Terceras 16 rondas
         rotations = [4,11,16,23];
         indices = [5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2];
         key="01101110110110011110101110100001";
         for(let j=0;j<16;j++){  
             let aux = bXor(arrAux[0],md5Function3(arrAux));
             aux = bXor(aux,arrWord[i+indices[j]]);
             aux = bXor(aux,key);
             aux = bLeftRotation(aux,rotations[j%4]);
             aux = bXor(aux,arrAux[1]);
             arrAux[2]=arrAux[1];
             arrAux[3]=arrAux[2];
             arrAux[0]=arrAux[3];
             arrAux[1]=aux;
         }
        
         //Cuartas 16 rondas
         rotations = [6,10,15,21];
         indices = [0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9];
         key="11011101101100111101011101000010";
         for(let j=0;j<16;j++){  
             let aux = bXor(arrAux[0],md5Function4(arrAux));
             aux = bXor(aux,arrWord[i+indices[j]]);
             aux = bXor(aux,key);
             aux = bLeftRotation(aux,rotations[j%4])
             aux = bXor(aux,arrAux[1]);
             arrAux[2]=arrAux[1];
             arrAux[3]=arrAux[2];
             arrAux[0]=arrAux[3];
             arrAux[1]=aux;
         }
         storedValues[0]=bXor(arrAux[0],storedValues[0]);
         storedValues[1]=bXor(arrAux[1],storedValues[1]);
         storedValues[2]=bXor(arrAux[2],storedValues[2]);
         storedValues[3]=bXor(arrAux[3],storedValues[3]);
    }
    return arrAux;
}


//FUNCION HASH SHA1
function sha1(text){
    let arrWord = init(text,false);
    let arrAux=[];
    arrAux[0]="01100111010001010010001100000001";
    arrAux[1]="11101111110011011010101110001001";
    arrAux[2]="10011000101110101101110011111110";
    arrAux[3]="00010000001100100101010001110110";
    arrAux[4]="00000011001001010100011101100001";
    let originalSize = arrWord.length;
    for(let i=originalSize;i>0;i-=16){
        let arrAux=[];
        for(let j=i;j<arrWord.length;j++){
            arrAux.push(arrWord[j]);
        }
        let j=0;
        for(j=0;j<64;j++){
            arrWord[i+j]=bLeftRotation(bXor(bXor(bXor(arrWord[i+j-3],arrWord[i+j-8]),arrWord[i+j-14]),arrWord[i+j-16]),1);
        }
        while(arrWord.length!=(i+j)){
            arrWord.pop();
        }
        arrWord=arrWord.concat(arrAux);
    }

    for(let i=0;i<arrWord.length;i+=80){
        let key=0;
        //Primeras 20 rondas
        key=0;
        key=addPadding(key.toString(2),32,"0");
        for(let j=0;j<20;j++){  
            let aux = bXor(arrAux[4],sha1Function1(arrAux));
            aux = bXor(aux,bLeftRotation(arrAux[0],5));
            aux = bXor(aux,arrWord[j]);
            aux = bXor(aux,key);
            arrAux[0]=aux;
            arrAux[1]=bLeftRotation(arrAux[1],30);
            //Desplazamiento de Registro de Vectores
            auxReg=arrAux[4];
            arrAux[4]=arrAux[3];
            arrAux[3]=arrAux[2];
            arrAux[2]=arrAux[1];
            arrAux[1]=arrAux[0];
            arrAux[0]=auxReg;
        }

        //Segundas 20 rondas
        key="01011010100000100111100110011001";
        for(let j=20;j<40;j++){  
            let aux = bXor(arrAux[4],sha1Function2_4(arrAux));
            aux = bXor(aux,bLeftRotation(arrAux[0],5));
            aux = bXor(aux,arrWord[j]);//Recuerda que la siguiente ronda sigue la numeracion
            aux = bXor(aux,key);
            arrAux[0]=aux;
            arrAux[1]=bLeftRotation(arrAux[1],30);
            //Desplazamiento de Registro de Vectores
            auxReg=arrAux[4];
            arrAux[4]=arrAux[3];
            arrAux[3]=arrAux[2];
            arrAux[2]=arrAux[1];
            arrAux[1]=arrAux[0];
            arrAux[0]=auxReg;
        }

         //Terceras 20 rondas
         key="01101110110110011110101110100001";
         for(let j=40;j<60;j++){  
            let aux = bXor(arrAux[4],sha1Function3(arrAux));
            aux = bXor(aux,bLeftRotation(arrAux[0],5));
            aux = bXor(aux,arrWord[j]);//Recuerda que la siguiente ronda sigue la numeracion
            aux = bXor(aux,key);
            arrAux[0]=aux;
            arrAux[1]=bLeftRotation(arrAux[1],30);
            //Desplazamiento de Registro de Vectores
            auxReg=arrAux[4];
            arrAux[4]=arrAux[3];
            arrAux[3]=arrAux[2];
            arrAux[2]=arrAux[1];
            arrAux[1]=arrAux[0];
            arrAux[0]=auxReg;
        }

         //Cuartas 20 rondas
         key="11011101101100111101011101000010";
         for(let j=60;j<80;j++){  
            let aux = bXor(arrAux[4],sha1Function2_4(arrAux));
            aux = bXor(aux,bLeftRotation(arrAux[0],5));
            aux = bXor(aux,arrWord[j]);//Recuerda que la siguiente ronda sigue la numeracion
            aux = bXor(aux,key);
            arrAux[0]=aux;
            arrAux[1]=bLeftRotation(arrAux[1],30);
            //Desplazamiento de Registro de Vectores
            auxReg=arrAux[4];
            arrAux[4]=arrAux[3];
            arrAux[3]=arrAux[2];
            arrAux[2]=arrAux[1];
            arrAux[1]=arrAux[0];
            arrAux[0]=auxReg;
        }
    }
    return arrAux;
}


//FUNCION HASH SHA256
function sha256(text){
    let arrWord = init(text,false);
    let arrAux=[];
    arrAux[0]="01100111010001010010001100000001";
    arrAux[1]="11101111110011011010101110001001";
    arrAux[2]="10011000101110101101110011111110";
    arrAux[3]="00010000001100100101010001110110";
    arrAux[4]="00000011001001010100011101100001";
    arrAux[5]="01011101011011100111111101001100";
    arrAux[6]="10010101000111011000010000001100";
    arrAux[7]="00011101100001000000110010010101";

    let originalSize = arrWord.length;
    for(let i=originalSize;i>0;i-=16){
        let arrAux=[];
        for(let j=i;j<arrWord.length;j++){
            arrAux.push(arrWord[j]);
        }
        let j=0;
        for(j=0;j<48;j++){
            arrWord[i+j]=bLeftRotation(bXor(bXor(bXor(arrWord[i+j-3],arrWord[i+j-8]),arrWord[i+j-14]),arrWord[i+j-16]),1);
        }
        while(arrWord.length!=(i+j)){
            arrWord.pop();
        }
        arrWord=arrWord.concat(arrAux);
    }
    
    for(let i=0;i<arrWord.length;i+=64){
        let key=0;
        //Primeras 16 rondas
        key=0;
        key=addPadding(key.toString(2),32,"0");
        for(let j=0;j<16;j++){
            let aux = bXor(arrAux[7],sha256FunctionCh(arrAux));
            aux = bXor(aux,bXor(arrWord[j],key));
            aux = bXor(aux,sha256FunctionE1(arrAux));
            arrAux[3] = bXor(aux,arrAux[3]);
            aux=bXor(aux,sha256FunctionMa(arrAux));
            aux=bXor(aux,sha256FunctionE0(arrAux));
            
            //Desplazamiento de Registro de Vectores
            arrAux[7]=arrAux[6];
            arrAux[6]=arrAux[5];
            arrAux[5]=arrAux[4];
            arrAux[4]=arrAux[3];
            arrAux[3]=arrAux[2];
            arrAux[2]=arrAux[1];
            arrAux[1]=arrAux[0];
            arrAux[0]=aux;
        }

        //Segundas 16 rondas
        key="01011010100000100111100110011001";
        for(let j=16;j<32;j++){
            let aux = bXor(arrAux[7],sha256FunctionCh(arrAux));
            aux = bXor(aux,bXor(arrWord[j],key));
            aux = bXor(aux,sha256FunctionE1(arrAux));
            arrAux[3] = bXor(aux,arrAux[3]);
            aux=bXor(aux,sha256FunctionMa(arrAux));
            aux=bXor(aux,sha256FunctionE0(arrAux));
            
            //Desplazamiento de Registro de Vectores
            arrAux[7]=arrAux[6];
            arrAux[6]=arrAux[5];
            arrAux[5]=arrAux[4];
            arrAux[4]=arrAux[3];
            arrAux[3]=arrAux[2];
            arrAux[2]=arrAux[1];
            arrAux[1]=arrAux[0];
            arrAux[0]=aux;
        }

         //Terceras 16 rondas
         key="01101110110110011110101110100001";
         for(let j=32;j<48;j++){
            let aux = bXor(arrAux[7],sha256FunctionCh(arrAux));
            aux = bXor(aux,bXor(arrWord[j],key));
            aux = bXor(aux,sha256FunctionE1(arrAux));
            arrAux[3] = bXor(aux,arrAux[3]);
            aux=bXor(aux,sha256FunctionMa(arrAux));
            aux=bXor(aux,sha256FunctionE0(arrAux));
            
            //Desplazamiento de Registro de Vectores
            arrAux[7]=arrAux[6];
            arrAux[6]=arrAux[5];
            arrAux[5]=arrAux[4];
            arrAux[4]=arrAux[3];
            arrAux[3]=arrAux[2];
            arrAux[2]=arrAux[1];
            arrAux[1]=arrAux[0];
            arrAux[0]=aux;
        }

         //Cuartas 16 rondas
         key="11011101101100111101011101000010";
         for(let j=48;j<64;j++){
            let aux = bXor(arrAux[7],sha256FunctionCh(arrAux));
            aux = bXor(aux,bXor(arrWord[j],key));
            aux = bXor(aux,sha256FunctionE1(arrAux));
            arrAux[3] = bXor(aux,arrAux[3]);
            aux=bXor(aux,sha256FunctionMa(arrAux));
            aux=bXor(aux,sha256FunctionE0(arrAux));
            
            //Desplazamiento de Registro de Vectores
            arrAux[7]=arrAux[6];
            arrAux[6]=arrAux[5];
            arrAux[5]=arrAux[4];
            arrAux[4]=arrAux[3];
            arrAux[3]=arrAux[2];
            arrAux[2]=arrAux[1];
            arrAux[1]=arrAux[0];
            arrAux[0]=aux;
        }
    }
    return arrAux;
}


//FUNCION HASH HMAC
function hmac(text,secret,isSha1) { 
    let sizeNeeded=512;
    let originalSecret=secret;
    let textBinary=textToBinaryBigEndian(text);
    let count1 = 0;
    let padding5C = ["0","1","0","1","1","1","0","0"];
    let padding36 = ["0","0","1","1","0","1","1","0"];
    let specialPadding="";
    //OBTENIENDO PRIMER PADDING
    while((textBinary.length+specialPadding.length) % sizeNeeded != 448){
        specialPadding=padding36[count1%padding36.length]+specialPadding;
        count1++;
    }
    if(secret.length>specialPadding.length){
        let newSpecialPadding="";
        let auxKey=secret.substring(0,specialPadding.length);
        for(let i=0;i<specialPadding.length;i++){
            newSpecialPadding+=bXor(auxKey.substring(i,i+1),specialPadding.substring(i,i+1));
        }
        specialPadding=newSpecialPadding;
    }else{
        let originalSize = secret.length;
        while((secret.length+originalSize)<=specialPadding.length){
            secret+=secret.substring(0,originalSize);
        }
        let auxKey=addPadding(secret,specialPadding.length,"0");
        let newSpecialPadding="";
        for(let i=0;i<specialPadding.length;i++){
            newSpecialPadding+=bXor(auxKey.substring(i,i+1),specialPadding.substring(i,i+1));
        }
        specialPadding=newSpecialPadding;
    }
    textBinary=specialPadding+textBinary;
    naturalText="";
    for(let i=0;i<textBinary.length;i+=8){
        let hexCode=parseInt(textBinary.substring(i,i+4),2).toString(16)+parseInt(textBinary.substring(i+4,i+8),2).toString(16);;
        naturalText+=String.fromCharCode(parseInt(hexCode,16));
    }
    //PRIMER SHA
    let auxShaResult;
    if(isSha1){
        auxShaResult=sha1(naturalText);
    }else{
        auxShaResult=sha256(naturalText);
    }
    textBinary="";
    for(let i=0;i<auxShaResult.length;i++){
        textBinary+=auxShaResult[i];
    }
    count1=0;
    specialPadding="";
    secret=originalSecret;
    //OBTENIENDO SEGUNDO PADDING
    
    while((textBinary.length+specialPadding.length) % sizeNeeded != 448){
        specialPadding=padding5C[count1%padding5C.length]+specialPadding;
        count1++;
    }
    if(secret.length>specialPadding.length){
        let newSpecialPadding="";
        let auxKey=secret.substring(0,specialPadding.length);
        for(let i=0;i<specialPadding.length;i++){
            newSpecialPadding+=bXor(auxKey.substring(i,i+1),specialPadding.substring(i,i+1));
        }
        specialPadding=newSpecialPadding;
    }else{
        let originalSize = secret.length;
        while((secret.length+originalSize)<=specialPadding.length){
            secret+=secret.substring(0,originalSize);
        }
        let auxKey=addPadding(secret,specialPadding.length,"0");
        let newSpecialPadding="";
        for(let i=0;i<specialPadding.length;i++){
            newSpecialPadding+=bXor(auxKey.substring(i,i+1),specialPadding.substring(i,i+1));
        }
        specialPadding=newSpecialPadding;
    }
    textBinary=specialPadding+textBinary;
    naturalText="";
    for(let i=0;i<textBinary.length;i+=8){
        let hexCode=parseInt(textBinary.substring(i,i+4),2).toString(16)+parseInt(textBinary.substring(i+4,i+8),2).toString(16);;
        naturalText+=String.fromCharCode(parseInt(hexCode,16));
    }
    //SEGUNDO SHA
    if(isSha1){
        auxShaResult=sha1(naturalText);
    }else{
        auxShaResult=sha256(naturalText);
    }
    return auxShaResult;
}


//PRIMERA FUNCION MD4
function md4Function1(arrAux){
    return bOr(bAnd(arrAux[1],arrAux[2]),bAnd(bNot(arrAux[1]),arrAux[3]));
}


//SEGUNDA FUNCION MD4
function md4Function2(arrAux){
    return bOr( bOr(bAnd(arrAux[1],arrAux[2]),bAnd(arrAux[1],arrAux[3])) , bAnd(arrAux[2],arrAux[3]) );
}


//TERCERA FUNCION MD4
function md4Function3(arrAux){
    return bXor(bXor(arrAux[1],arrAux[2]),arrAux[3]);
}


//PRIMERA FUNCION MD5
function md5Function1(arrAux){
    return bOr(bAnd(arrAux[1],arrAux[2]),bAnd(bNot(arrAux[1]),arrAux[3]));
}


//SEGUNDA FUNCION MD5
function md5Function2(arrAux){
    return bOr(bAnd(arrAux[1],arrAux[3]),bAnd(arrAux[2],bNot(arrAux[3])));
}


//TERCERA FUNCION MD5
function md5Function3(arrAux){
    return bXor(bXor(arrAux[1],arrAux[2]),arrAux[3]);
}


//CUARTA FUNCION MD5
function md5Function4(arrAux){
    return bXor(arrAux[2],bOr(arrAux[1],bNot(arrAux[3])));
}


//PRIMERA FUNCION SHA1
function sha1Function1(arrAux){
    return bOr(bAnd(arrAux[1],arrAux[2]),bAnd(bNot(arrAux[1]),arrAux[3]));
}


//SEGUNDA Y CUARTA FUNCION SHA1
function sha1Function2_4(arrAux){
    return bXor(bXor(arrAux[1],arrAux[2]),arrAux[3]);
}


//TERCERA FUNCION SHA1
function sha1Function3(arrAux){
    return bOr(bOr(bAnd(arrAux[1],arrAux[2]),bAnd(arrAux[1],arrAux[3])),bAnd(arrAux[2],arrAux[3]));
}


//FUNCION CH DE SHA256
function sha256FunctionCh(arrAux){
    return bXor(bAnd(arrAux[4],arrAux[5]),bAnd(bNot(arrAux[4]),arrAux[6]));
}


//FUNCION MA DE SHA256
function sha256FunctionMa(arrAux){
    return bXor(bXor(bAnd(arrAux[0],arrAux[1]),bAnd(arrAux[0],arrAux[2])),bAnd(arrAux[1],arrAux[2]));
}


//FUNCION E0 DE SHA256
function sha256FunctionE0(arrAux){
    return bXor(bXor(bRightRotation(arrAux[0],2),bRightRotation(arrAux[0],13)),bRightRotation(arrAux[0],22));
}


//FUNCION E1 DE SHA256
function sha256FunctionE1(arrAux){
    return bXor(bXor(bRightRotation(arrAux[4],6),bRightRotation(arrAux[4],11)),bRightRotation(arrAux[4],25));
}   


//FUNCION QUE PREPARA EL TEXTO PLANO Y SU EXTENSIÓN EN UN ARREGLO DE BINARIOS
function init(text,isLittleEndian){
    if(isLittleEndian)
        text=textToBinaryLittleEndian(text);
    else
        text=textToBinaryBigEndian(text);
    let originalSize = text.length;
    let padding = 1;
    while(text.length % 512 != 448){
        text+=padding;
        padding=0;
    }
    lenghtAdd=originalSize.toString(2);
    while(lenghtAdd.length != 64){
        lenghtAdd="0"+lenghtAdd;    
    }
    text+=lenghtAdd;
    let arrWord=[];
    for(let i=0;i<text.length;i+=32){
        arrWord.push(text.substring(i,i+32));
    }
    return arrWord;
}


//FUNCION DE TRANSFORMACION DE TEXTO A BINARIO EN LITTLE ENDIAN
function textToBinaryLittleEndian(text){
    let result="";
    textValue = text;
    textClean = decodeURI(encodeURI(textValue));
    let binaryWord=0;
    for(let i=textClean.length-1;i>=0;i--){
        binaryWord = textClean.charCodeAt(i);
        binaryWord = binaryWord.toString(2);
        while(binaryWord.length % 8 != 0){
            binaryWord = "0"+binaryWord;
        }

        result+=binaryWord;

    }
    return result;
}


//FUNCION DE TRANSFORMACION DE TEXTO A BINARIO EN BIG ENDIAN
function textToBinaryBigEndian(text){
    let result="";
    textValue = text;
    textClean = decodeURI(encodeURI(textValue));
    let binaryWord=0;
    for(let i=0;i<textClean.length;i++){
        binaryWord = textClean.charCodeAt(i);
        binaryWord = binaryWord.toString(2);
        while(binaryWord.length % 8 != 0){
            binaryWord = "0"+binaryWord;
        }

        result+=binaryWord;

    }
    return result;
}


//OPERACION DE PADDING
function addPadding(text,toLenght,paddingValue){
    while(text.length<toLenght){
        text = paddingValue + text;
    }
    return text;
}


//OPERACION AND
function bAnd(bits1,bits2){
    if(bits1.length == bits2.length){
        let result = parseInt(bits1, 2)&parseInt(bits2, 2);
        result = result.toString(2);
        if(result.substring(0,1)=="-"){
            result = result.substring(1, result.length);
        }
        result=addPadding(result,bits1.length,"0");
        return result;
    }else{
        console.log("Cadenas de Bits de Longitud Diferente en And");
        return null;
    }
}


//OPERACION OR
function bOr(bits1,bits2){
    if(bits1.length == bits2.length){
        let result = parseInt(bits1, 2)|parseInt(bits2, 2);
        result = result.toString(2);
        if(result.substring(0,1)=="-"){
            result = result.substring(1, result.length);
        }
        result = addPadding(result,bits1.length,"0");
        return result;
    }else{
        console.log("Cadenas de Bits de Longitud Diferente en Or");
        return null;
    }
}


//OPERACION NOT
function bNot(bits){
    let result = ~parseInt(bits, 2);
    result = result.toString(2);
    if(result.substring(0,1)=="-"){
        result="0"+result.substring(2,result.length);
        result = addPadding(result,bits.length,"1");
    }else{
        result = addPadding(result,bits.length,"0");
    }
    return result;    
}


//OPERACION XOR
function bXor(bits1,bits2){
    if(bits1.length == bits2.length){
        let result = parseInt(bits1, 2)^parseInt(bits2, 2);
        result = result.toString(2);
        if(result.substring(0,1)=="-"){
            result = result.substring(1, result.length);
        }
        result = addPadding(result,bits1.length,"0");
        return result;
    }else{
        console.log("Cadenas de Bits de Longitud Diferente en Xor");
        return null;
    }
}


//METODO DE ROTACION A LA IZQUIERDA
function bLeftRotation(bits,nPositions){
    nPositions = nPositions % bits.length;
    return bits.substring(nPositions,bits.length)+bits.substring(0,nPositions)
}

//METODO DE ROTACION A LA DERECHA
function bRightRotation(bits,nPositions){
    nPositions = nPositions % bits.length;
    return bits.substring(bits.length-nPositions,bits.length)+bits.substring(0,bits.length-nPositions);
}