// FEAL.js
// Seth Wilson
// CYBR 537 Applied Encryption and Cryptography
// May 1, 2020

// This program implements the Fast Data Encipherment Algorithm (FEAL)
// proposed by Akihiro Shimizu and Shoji Miyaguchi in their 1988 paper. 
//
// The key processing method transforms the user-supplied 64-bit key  
// into a set of 16 16-bit keys for use in the encipherment and 
// decipherment algorithms.
//
// The enciphering method encrypts a 64-bit user-supplied plaintext
// into ciphertext using the extended key created by the key processing
// method. 
//
// The deciphering method decrypts a 64-bit user-supplied ciphertext
// into a 64-bit plaintext using the extended key. 
//
// The speed test method allows a user to compare his or her processing 
// power to the power cited in the original paper. 
//
// The function names f, fK, and S were the ones originally used by 
// Akihiro Shimizu and Shoji Miyaguchi in their paper.

var key = [];	//user-defined 64-bit key
var xkey = [];	//calculated extended key
var mtext = [];	//64-bit plaintext message
var ctext = [];	//64-bit ciphertext 
var alpha = [];	//input to function_fk & function_f
var beta = [];	//input to function_fk & function_f
var fk = [];	//output of function_fk
var ff = [];	//output of function_f
var kpA = [];	//working variable in function_S
var kpB = [];	//working variable in function_S
var kpD = [];	//working variable in function_S
var phi = [];	//64-bit constant = 0
var edR = [];	//right side working variable
var edL = [];	//left side working variable

function reset_arrays() {
	key =  [0,0,0,0,0,0,0,0]; //64 bits
	xkey = [0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0,
			0,0,0,0,0,0,0,0]; //256 bits
	mtext =  [0,0,0,0,0,0,0,0]; 
	ctext =  [0,0,0,0,0,0,0,0];

	alpha = [0, 0, 0, 0];
	beta =  [0, 0, 0, 0];

	fk = [0, 0, 0, 0];
	ff = [0, 0, 0, 0];

	kpA = [0, 0, 0, 0];
	kpB = [0, 0, 0, 0];
	kpD = [0, 0, 0, 0];
	phi = [0, 0, 0, 0];
	
	edR = [0, 0, 0, 0];
	edL = [0, 0, 0, 0];
	
}

function function_fK() {
	//function fK defined in Section 2.2 of Shimizu & Miyaguchi
	//input value of 00 00 00 00 will output 10 04 10 44 (FEAL-NX SPECIFICATIONS)
	fk[1] = alpha[1] ^ alpha[0];
	fk[2] = alpha[2] ^ alpha[3];
	fk[1] = function_S( fk[1], fk[2] ^ beta[0], 1 );
	fk[2] = function_S( fk[2], fk[1] ^ beta[1], 0 );
	fk[0] = function_S( alpha[0], fk[1] ^ beta[2], 0 );
	fk[3] = function_S( alpha[3], fk[2] ^ beta[3], 1 );
}

function function_S( x1, x2, delta) {
	//function S defined in Section 2.1 
	var t = 0;
	t = ( x1 + x2 + delta ) % 256;
	return ( (t << 2) % 256 + ( t >> 6 ) );
}


function hex_key_to_key_array() {
	//put the key value from the form into the key array
	i=0;
	s=(document.getElementById("key_hex")).value;
	while( i < key.length && i * 2 < s.length ) {
		key[i] = parseInt( "0x" + s[i * 2] + s[i * 2 + 1]);
		i++;
	}
	if( i < s.length ) {key[i] = key[i] << 4;}
	i++;
	while( i < key.length ) { 
		key[i] = 0;
		i++;
	}
}

function hex_to_array(s, a) {
	//put the hex value s into array a
	i=0;
	while( i < a.length ) {
		if ( i * 2 < s.length ) {
			a[i] = parseInt( "0x" + s[i * 2] + s[i * 2 + 1]);
			if(( i * 2 + 1 ) == s.length ) {a[i] = a[i] << 4;}
		}
		else { a[i] = 0; }
		i++;
	}
}

function display_hex_extended_key() {
	//display the values in the extended key array
	var d=document.getElementById("div_extended_key");
	var s="";
	var i=0;
	while ( i < xkey.length ) {
		s = s + ("0" + xkey[i].toString(16)).toUpperCase().substr(-2) + (( i % 2 > 0 ) ? " " : "");
		i++;
	}
	d.innerHTML = s;
}

function display_ciphertext_output() {
	//display ciphtertext in div_ciphertext_output
	var d=document.getElementById("div_ciphertext_output");
	var s="";
	var i=0;
	while ( i < ctext.length ) {
		s = s + ("0" + ctext[i].toString(16)).toUpperCase().substr(-2); // + (( i % 2 > 0 ) ? " " : "");
		i++;
	}
	d.innerHTML = s;
}

function display_plaintext_output() {
	//display plaintext in div_plainttext_output
	var d=document.getElementById("div_plaintext_output");
	var s="";
	var i=0;
	while ( i < mtext.length ) {
		s = s + ("0" + ctext[i].toString(16)).toUpperCase().substr(-2); // + (( i % 2 > 0 ) ? " " : "");
		i++;
	}
	d.innerHTML = s;
}

function copy_ciphertext_click() {
	encrypt_block();
	document.getElementById("hex_ciphertext").value = document.getElementById("div_ciphertext_output").innerHTML;
	
}

function feal8_key_processing() {
	//Calculation of extended key from Section 3
	//from Shimizu & Miyaguchi input of 0123456789ABCDEF
	//output DF 3B CA 36 F1 7C 1A EC 45 A5 B9 C7 26 EB AD 25 
	//       8B 2A EC B7 AC 50 9D 4C 22 CD 47 9B A8 D5 0C B5 
	
	//Calculate A0, B0, and D0
	i = 0;
	while ( i < 4 ) {
		kpA[i] = key[i]; //left side of key
		kpB[i] = key[i+4]; //right side of key
		kpD[i] = phi[i]; //set to phi which is 0
		i++;
	}
	
	//Calculate 16-bit values K0 to K15
	r = 1;
	while ( r < 9 ) {
		i=0;
		while( i < 4 ) {
			alpha[i] = kpA[i]; //set alpha to A of previous round
			beta[i] = kpB[i] ^ kpD[i]; //set beta to B previous XOR D previous
			i++;
		}
		function_fK();
		i = 0;
		while( i < 4 ) {
			kpD[i] = kpA[i]; //set D to previous A for next round
			kpA[i] = kpB[i]; //set A to previous B for next round
			kpB[i] = fk[i]; //set B to fk return value for next round
			i++;
		}
		i = (r - 1) * 4;
		xkey[i] = fk[0]; // K2(r-1) = Br0, Br1
	    xkey[i+1] = fk[1]; // K2(r-1) = Br0, Br1
		xkey[i+2] = fk[2]; // K2(r-1) = Br2, Br3
		xkey[i+3] = fk[3]; // K2(r-1) = Br2, Br3
		r++;
	}
}

function function_f(){
	//data randomization function 
	//function f defined in Section 2.3 of Shimizu & Miyaguchi
	//alpha is 32 bits
	//beta is 16 bits
	
	ff[1] = alpha[1] ^ beta[0] ^ alpha[0];
	ff[2] = alpha[2] ^ beta[1] ^ alpha[3];
	ff[1] = function_S( ff[1], ff[2], 1 );
	ff[2] = function_S( ff[2], ff[1], 0 );
	ff[0] = function_S( alpha[0], ff[1], 0 );
	ff[3] = function_S( alpha[3], ff[2], 1 );	
}

function feal8_enciphering_procedure(){
	//enciphering procedure defined in Section 4.1 of Shimizu & Miyaguchi
	
	//copy plaintext message into L0 and R0
	i=0;
	while( i < 4 ) {
		edL[i] = mtext[i];
		edR[i] = mtext[i+4];
		i++;
	}
	
	//XOR L0, R0 with K8, K9, K10, K11
	edL[0] = edL[0] ^ xkey[ 8*2 ];		//K8
	edL[1] = edL[1] ^ xkey[ 8*2+1 ];	//K8
	edL[2] = edL[2] ^ xkey[ 9*2 ];		//K9
	edL[3] = edL[3] ^ xkey[ 9*2+1 ]; 	//K9
	edR[0] = edR[0] ^ xkey[ 10*2 ];		//K8
	edR[1] = edR[1] ^ xkey[ 10*2+1 ];	//K8
	edR[2] = edR[2] ^ xkey[ 11*2 ];		//K9
	edR[3] = edR[3] ^ xkey[ 11*2+1 ]; 	//K9
	
	//XOR L0, R0 with PHI, L0
	//L0 XOR PHI = L0
	i=0;
	while( i < 4 ) {
		edR[i] = edR[i] ^ edL[i]; // R0 XOR L0
		i++;
	}
	
	//data randomizer rounds
	r=1;
	while( r < 9 ) {
		//calculate Rr = L(r-1) XOR f( R(r-1), K(r-1)
		// then Lr = R(r-1)
		i=0;
		while( i < 4 ) {
			alpha[i] = edR[i];
			i++;
			} //alpha = R(r-1)
		beta[0] = xkey[ (r - 1) * 2 ];	//beta = K(r-1)
		beta[1] = xkey[ (r - 1) * 2 + 1 ]; 
		beta[2] = 0; 
		beta[3] = 0; 
		
		//calculate // R(r) = L(r-1) XOR f( R(r-1), K(r-1))
		//L(r) = R(r-1)
		function_f();
		i=0;
		while( i < 4 ) {
			edR[i] = edL[i] ^ ff[i];
			edL[i] = alpha[i];
			i++;
			} 
		r++;
	}

	//XOR R8, L8 with PHI, R8
	//R8 XOR PHI = R8
	i=0;
	while( i < 4 ) {
		edL[i] = edL[i] ^ edR[i]; // L8 XOR R8
		i++;
	}

	//XOR R8, L8 with K12, K13, K14, K15
	edR[0] = edR[0] ^ xkey[ 12*2 ];		//K12
	edR[1] = edR[1] ^ xkey[ 12*2+1 ];	//K12
	edR[2] = edR[2] ^ xkey[ 13*2 ];		//K13
	edR[3] = edR[3] ^ xkey[ 13*2+1 ]; 	//K13
	edL[0] = edL[0] ^ xkey[ 14*2 ];		//K14
	edL[1] = edL[1] ^ xkey[ 14*2+1 ];	//K14
	edL[2] = edL[2] ^ xkey[ 15*2 ];		//K15
	edL[3] = edL[3] ^ xkey[ 15*2+1 ]; 	//K15
	
	//ciphertext is (R8, L8)
	i=0;
	while ( i < 4 ) {
		ctext[i] = edR[i];
		ctext[i+4] = edL[i];
		i++;
	}
	
}

function feal8_deciphering_procedure(){
	//deciphering procedure defined in Section 4.2 of Shimizu & Miyaguchi
	
	//copy plaintext message into L0 and R0
	i=0;
	while( i < 4 ) {
		edR[i] = ctext[i]; //left and right are swapped
		edL[i] = ctext[i+4];
		i++;
	}

	//XOR R8, L8 with K12, K13, K14, K15
	edR[0] = edR[0] ^ xkey[ 12*2 ];		//K12
	edR[1] = edR[1] ^ xkey[ 12*2+1 ];	//K12
	edR[2] = edR[2] ^ xkey[ 13*2 ];		//K13
	edR[3] = edR[3] ^ xkey[ 13*2+1 ]; 	//K13
	edL[0] = edL[0] ^ xkey[ 14*2 ];		//K14
	edL[1] = edL[1] ^ xkey[ 14*2+1 ];	//K14
	edL[2] = edL[2] ^ xkey[ 15*2 ];		//K15
	edL[3] = edL[3] ^ xkey[ 15*2+1 ]; 	//K15

	//XOR R8, L8 with PHI, R8
	//R8 XOR PHI = R8
	i=0;
	while( i < 4 ) {
		edL[i] = edL[i] ^ edR[i]; // L8 XOR R8
		i++;
	}
	
	//data randomizer rounds
	r=8;
	while( r > 0 ) {
		//calculate L(r-1) = R(r) XOR f( L(r), K(r-1) )
		// then R(r-1) = L(r)
		i=0;
		while( i < 4 ) {
			alpha[i] = edL[i];
			i++;
			} //alpha = L(r-1)
		beta[0] = xkey[ (r - 1) * 2 ];	//beta = K(r-1)
		beta[1] = xkey[ (r - 1) * 2 + 1 ]; 
		beta[2] = 0; 
		beta[3] = 0; 
		
		//calculate // L(r-1) = R(r) XOR f( L(r), K(r-1))
		//R(r-1) = L(r-1)
		function_f();
		i=0;
		while( i < 4 ) {
			edL[i] = edR[i] ^ ff[i];
			edR[i] = alpha[i];
			i++;
			} 
		r--;
	}

	//XOR L0, R0 with PHI, L0
	//L0 XOR PHI = L0
	i=0;
	while( i < 4 ) {
		edR[i] = edR[i] ^ edL[i]; // R0 XOR L0
		i++;
	}
	
	//XOR L0, R0 with K8, K9, K10, K11
	edL[0] = edL[0] ^ xkey[ 8*2 ];		//K8
	edL[1] = edL[1] ^ xkey[ 8*2+1 ];	//K8
	edL[2] = edL[2] ^ xkey[ 9*2 ];		//K9
	edL[3] = edL[3] ^ xkey[ 9*2+1 ]; 	//K9
	edR[0] = edR[0] ^ xkey[ 10*2 ];		//K8
	edR[1] = edR[1] ^ xkey[ 10*2+1 ];	//K8
	edR[2] = edR[2] ^ xkey[ 11*2 ];		//K9
	edR[3] = edR[3] ^ xkey[ 11*2+1 ]; 	//K9


	//plaintext is (L8, R8)
	i=0;
	while ( i < 4 ) {
		ctext[i] = edL[i];
		ctext[i+4] = edR[i];
		i++;
	}
	
}

function generate_extended_key() {
	
	reset_arrays();
	
	hex_key_to_key_array();
	
	//the parity option ignores the lowest bit of each byte of the key
	if ( document.getElementById("checkbox_parity").checked ) {
		var i=0;
		while ( i < key.length ) {
			key[i] = key[i] & 254;
			i++;
		}
	}
	
	feal8_key_processing();

	display_hex_extended_key();
}

function encrypt_block() {
	generate_extended_key();

	//load message plaintext into mtext array
	hex_to_array( document.getElementById("hex_message").value, mtext );
	feal8_enciphering_procedure();
	
	display_ciphertext_output();
	
}

function decrypt_block() {
	generate_extended_key();

	//load message ciphertext into ctext array
	hex_to_array( document.getElementById("hex_ciphertext").value, ctext );
	feal8_deciphering_procedure();
	
	display_plaintext_output();
	
}

function speed_test() {
	encrypt_block();
	
	var starttime = new Date();
	var endtime = null; 
	var i=0, j=0, n=0;
	
	//first get a rough idea of how many times a second 
	while ( Date.now() - starttime.getTime() < 1000 ) {
		i=0;
		while( i < 4 ) {
			mtext[i] = ctext[i];
			i++;
		}
		feal8_enciphering_procedure();
		n++;
	}
	
	//next get a better estimate by eliminating date object overhead
	j = n * 3;
	starttime = null;
	starttime = (new Date()).getTime();
	while( j > 0 ) {
		i=0;
		while( i < 4 ) {
			mtext[i] = ctext[i];
			i++;
		}
		feal8_enciphering_procedure();
		j--;
	}
	endtime = (new Date()).getTime();
	
	n=Math.floor( n * 3 * 64 / ( endtime - starttime ))
	var s = "Speed Test Result: " + n.toString() + " kbps <br>";
	document.getElementById("div_speed_test_result").innerHTML = s;
	
	encrypt_block();
}
















