# KNAP

# ¿Para qué sirve?
KNAP son las siglas de __Known Nearby Access Points__. Es un script programado en python3 que muestra por pantalla las ESSIDS de las probes que envian los dispositivos cercanos al activar el wifi, reconectarse a otro punto de acceso, o cada poco rato. 

En palabras más sencillas, `muestra el nombre de los wifis a los que se han conectado anteriormente los dispositivos cercanos`.
Esto aplica a casi cualquier dispositivo con acceso a wifi que se haya conectado anteriormente a uno, aunque no siempre se muestran todos.

# ¿Cómo funciona?
Imagina que te vas de viaje. Estás en el aeropuerto y decides conectarte con tu teléfono al wifi público que proporciona.
Vamos a llamarlo `aeropuerto_wifi` y es una red abierta sin contraseña.

Después de tu viaje, vuelves a casa y sigues con tu vida, olvidando completamente acerca de ese wifi, ya que no estás en el aeropuerto.
El problema es que tu teléfono no lo ha olvidado. Cada vez que activas el wifi, te desconectas de una red o en general, cada cierto rato, tu teléfono envia unos paquetes llamados `probes` que buscan si estás cerca de alguna red wifi a la que 
te conectaste en el pasado. 

Esto lo hace con la finalidad de, que si encuentra alguna, se conecte automaticámente sin necesidad de hacerlo manualmente. 
Pues bien, lo grave es que tu teléfono no valida ningun parámetro aparte del nombre y la contraseña de la red (que en el caso de que la red sea abierta, solo depende del nombre). 

Es decir, que si alguien crea un punto de acceso (wifi) llamado `aeropuerto_wifi`, tu teléfono se conectará automáticamente pensando que es el wifi al que te conectaste allí.

![alt text](https://i.imgur.com/nIfxW37.jpeg)
> Un hacker puede crear un punto de acceso falso para que tu teléfono se conecte automáticamente a él

# Funciones del script
El script "escucha" los probes de alrededor que envian los dispositivos y extrae el ESSID del wifi que buscan. Posteriormente, se muestra por pantalla y opcionalmente se puede mostrar el fabricante de cada dispositivo. 
Adicionalmente el script guarda las redes encontradas en un archivo `essids.txt` de forma ordenada y sin repetir redes.


# INSTALACIÓN Y USO
La descarga e instalación es muy fácil:
```
git clone https://github.com/Samilososami/knap
cd knap
pip3 install -r requirements.txt
python3 knap.py
```


Y el uso es sencillo, rápido e intuitivo, usa argparse para lanzar la herramienta directamente.
```
python3 knap.py -i <interfaz>
```
La interfaz debe estar en modo monitor previamente para poder capturar paquetes. En caso de que no lo esté el script lo avisa junto al comando que se debe ejecutar para ponerla en dicho modo.

# MACs y fabricantes
El script incluye un archivo `oui.txt` con una enorme cantidad de fabricantes y sus respectivas direcciones MAC. 
En un principio había pensado en hacer el script utlizando requests para evitar la necesidad de descargar y utilizar un archivo, pero de esta forma se pueden matar procesos conflictivos sin que afecte al funcionamiento del script.

Gracias a esto se pueden mostrar los nombres de los fabricantes al lado de cada wifi en vez de visualizar únicamente la MAC.
```
python3 knap.py -i <interfaz> -oui oui.txt
```
El archivo `oui.txt` se puede descargar desde [aquí](https://standards-oui.ieee.org/oui/oui.txt)

# Vectores de ataque
Tras ejecutar el ataque y enumerar las essids que buscan los dispositivos, se puede crear un captive portal o cualquier tipo de hotspot de forma que el dispositvo que busca la red se conecte automáticamente, se puede ejecutar un ataque Man In The Middle o se puede simplemente tratar de enumerar y comprometer el dispositivo conectado. Las posibilidades son casi ilimitadas :')

__KNOWN BEACONS:__ este ataque es, por decirlo así, la segunda parte del script. Se proporciona una lista de redes wifi, como el `essids.txt`. El ataque las crea, de forma que varios clientes de conecten irremediablemente. 
> ⚠ El ataque solo funcionará en caso de que el dispositivo que busca las redes tenga activada la función "activar automaticamente"

 
# ADVERTENCIAS Y ENLACES
Este script está hecho con la única finalidad de utilizarlo contra tus dispositivos o contra los que tengas el permiso. Al momento de ejecutar el script la responsabilidad de su uso recae completamente en el usuario.

_[KNOWN BEACONS](https://census-labs.com/news/2018/02/01/known-beacons-attack-34c3/)_

_[PROBE SNIFFING](https://www.oreilly.com/library/view/kali-linux-wireless/9781783280414/ch10s03.html)_

_[CAPTIVE PORTAL](https://es.wikipedia.org/wiki/Portal_cautivo)_

Ante cualquier duda contáctame en samilososami@gmail.com :)
