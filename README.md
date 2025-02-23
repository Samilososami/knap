# KNAP

# ¿Para qué sirve?
KNAP son las siglas de _Known Nearby Access Points_. Es un script programado en python3 que muestra por pantalla las ESSIDS de las probes que envian los dispositivos cercanos al activar el wifi, reconectarse a otro punto de acceso, o cada poco rato. 

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


# INSTALACIÓN Y USO
La descarga e instalación es muy fàcil:
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
La interfaz debe estar en modo monitor previamente para poder capturar paquetes. En caso de que no lo esté el script lo avisa junto al comando que se debe ejecutar para ponerla en modo monitor.

# MACs y fabricantes
El script incluye un arcivo `oui.txt` con una enorme cantidad de fabricantes y sus respectivas direcciones MAC. 
En un principio había pensado en hacer el script utlizando requests para evitar la necesidad de descargar y utilizar un archivo, pero de esta forma se pueden matar procesos conflictivos sin que afecte al funcionamiento del script.

```
python3 knap.py -i <interfaz> -oui oui.txt
```
