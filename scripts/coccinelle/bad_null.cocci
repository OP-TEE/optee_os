/**
* SPDX-License-Identifier: BSD-2-Clause
*
*/

/************************************************************************************
 * This semantic patch is responsible of replacing "foo *= NULL" expressions, into 
 * the equivalent contracted form.
 * 
 */
@rule1@
expression E;
@@

(
-   E == NULL
+   !E
| 
-   NULL == E
+   !E
|
-   E != NULL
+   E
|
-   NULL != E
+   E
)


@rule2@
expression E;
identifier f;
@@

E = f(...)
<...
( 
- E == NULL
+ !E
| 
- E != NULL
+ E
| 
- NULL == E
+ !E
| 
- NULL != E
+ E
)
...>

