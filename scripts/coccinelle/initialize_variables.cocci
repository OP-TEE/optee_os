/************************************************************************************
* This semantic patch matches all occurrencies of variable declaration without 
* initialization and then initializes them accordingly to their type.
*   
*   e.g.
*   -   int a;
*   +   int a = 0;
*
*/

@variable_declaration@
identifier v, n;
type t;
type numeric = {
	short, short int, signed short, signed short int, unsigned short, unsigned short int,
	int, signed, signed int, unsigned, unsigned int, long, long int, signed long, signed long int,
	unsigned long, unsigned long int, long long, long long int, signed long long, 
	signed long long int, unsigned long long, unsigned long long int,
	float, double, long double, size_t
};
@@

(
//  generic char
char v
+ = NULL
;
|
//  numeric
numeric v
+ = 0
;
|
//  size_t array
size_t v[]
+ = {0}
;
|
//  generic array
t v[]
+ = {NULL}
;
|
//  pointer type
t* v
+ = NULL
;
|
//  every other type
t v
+ = NULL
;
)

