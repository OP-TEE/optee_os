/************************************************************************************
 * This semantic patch signals possible cases of overflow.
 * Currently we are only looking for the following construct:
 *      if(a + b > c)     
 * 
 */

@r1@
identifier A, B, C;
binary operator add = {+};
binary operator gt = {>};
position p1;
@@

(
if@p1 (A add B gt C) {...}
)

@script:python@
p1 << r1.p1;
@@

coccilib.report.print_report(p1[0], "Warning, Possible overflow")

