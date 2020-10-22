USE freki;
DELIMITER $$
CREATE PROCEDURE my_procedure()
BEGIN
DECLARE cuenta INT DEFAULT 1;
SELECT COUNT(*)
INTO cuenta 
FROM rule;
IF cuenta < 1 THEN
INSERT INTO rule (name, rule) values('Tokendespues20160131', 'rule Tokendespues20160131\r\n{\r\n strings:\r\n $a = /TOKEN_20(1[6-9]|[2-3][0-9])-(0{,1}[1-9]|1[0-2])-(0{,1}[1-9]|2[0-9]|3[0-1])_\\d{6}/ \r\n condition:\r\n   $a\r\n}');
INSERT INTO rule (name, rule) values('TC_Identificada', 'rule TC_Identificada\r\n{\r\n strings:\r\n $tc1 = /347(\\d{13})/ \r\n $tc2 = /(6541|6556)(\\d{12})/ \r\n $tc3 = /389(\\d[0-9]{11})/ \r\n $tc4 = /9(\\d{15})/ \r\n $tc5 = /(5[1-5][0-9]{14}|2(22[1-9][0-9]{12}|2[3-9][0-9]{13}|[3-6][0-9]{14}|7[0-1][0-9]{13}|720[0-9]{12}))/ \r\n $tc6 = /4(\\d{15})/ \r\n condition:\r\n   $tc1 or $tc2 or $tc3 or $tc4 or $tc5 or $tc6 \r\n}');
END IF;
END$$
DELIMITER ;
-- Execute the procedure
CALL my_procedure();

-- Drop the procedure
DROP PROCEDURE my_procedure;
