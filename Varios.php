<?php

/**
 * Created by IntelliJ IDEA.
 * User: fbohn
 * Date: 16/11/15
 * Time: 12:54.
 */

namespace SIU\AraiUsuarios\Util;

use Psr\Log\LoggerInterface;
use SIU\AraiUsuarios\Error;
use Symfony\Component\Cache\Adapter\AbstractAdapter;
use Symfony\Component\Cache\Adapter\ApcuAdapter;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Adapter\MemcachedAdapter;

class Varios
{
    /* @var LoggerInterface $logger */
    protected $logger;

    const CADENA_ESPECIALES = 'ÀÁÂÃÄÅàáâãäåÈÉÊËèéêëÌÍÎÏìíîïÒÓÔÕÖØòóôõöøðÙÚÛÜùúûüÿýÝçÇÑñ';
    const CADENA_BASICOS = 'AAAAAAaaaaaaEEEEeeeeIIIIiiiiOOOOOOoooooooUUUUuuuuyyYcCNn';

    /**
     * @param LoggerInterface $logger
     */
    public function __construct(LoggerInterface $logger)
    {

        $this->logger = $logger;
    }

    public function getLogger()
    {
        return $this->logger;
    }

    /**
     * Hashes a password and returns the hash based on the specified encType.
     *
     * @param string $passwordPlano The password to hash in clear text
     * @param string $algoritmo     Standard LDAP encryption type which must be one of
     *                              crypt, md5, sha, smd5, ssha, or ''
     *
     * @return string The hashed password
     *
     * @throws Error
     */
    public function passwordHash($passwordPlano, $algoritmo = '')
    {
        $algoritmo = strtolower($algoritmo);
        switch ($algoritmo) {
            case 'crypt':
                if (!defined('CRYPT_BLOWFISH') || CRYPT_BLOWFISH == 0) {
                    throw new Error('La libreria de encriptación no soporta blowfish.');
                }
                // Hardcoded to second blowfish version and set number of rounds
                $password = crypt($passwordPlano, ((version_compare(PHP_VERSION, '5.3.7') < 0) ? '$2a$' : '$2y$').'10$'.$this->randomSalt(22));
                break;
            case 'md5':
                $password = base64_encode(pack('H*', md5($passwordPlano)));
                break;
            case 'sha':
                // Use php 4.3.0+ sha1 function, if it is available.
                if (function_exists('sha1')) {
                    $password = base64_encode(pack('H*', sha1($passwordPlano)));
                } elseif (function_exists('mhash')) {
                    $password = base64_encode(mhash(MHASH_SHA1, $passwordPlano));
                } else {
                    throw new Error('La instalación de PHP no tiene la función mhash(). No se puede encriptar con SHA.');
                }
                break;
            case 'ssha':
                if (function_exists('hash')) {
                    mt_srand((float) microtime() * 1000000);
                    $salt = $this->keygen_s2k('sha1', $passwordPlano, substr(pack('h*', md5(mt_rand())), 0, 8), 4);
                    $password = base64_encode(hash('sha1', $passwordPlano.$salt, true).$salt);
                } else {
                    throw new Error('La instalación de PHP no tiene la función hash(). No se puede encriptar con S2K.');
                }

                break;
            case 'smd5':
                if (function_exists('mhash') && function_exists('mhash_keygen_s2k')) {
                    mt_srand((float) microtime() * 1000000);
                    $salt = mhash_keygen_s2k(MHASH_MD5, $passwordPlano, substr(pack('h*', md5(mt_rand())), 0, 8), 4);
                    $password = base64_encode(mhash(MHASH_MD5, $passwordPlano.$salt).$salt);
                } else {
                    throw new Error('La instalación de PHP no tiene la función mhash() o la función mhash_keygen_s2k(). No se puede encriptar con S2K.');
                }
                break;
            case '':
            case 'plano':
                $password = $passwordPlano;
                break;
            default:
                throw new Error('Algoritmo de encriptación no válido. Utilice: crypt, ssha, smd5, md5, sha o plano.');
        }

        return $password;
    }

    /**
     * Given a clear-text password and a hash, this function determines if the clear-text password
     * is the password that was used to generate the hash. This is handy to verify a user's password
     * when all that is given is the hash and a "guess".
     *
     * @param string $passwordEncriptado The hash
     * @param $algoritmo
     * @param string $passwordPlano The password in clear text to test
     *
     * @return bool True if the clear password matches the hash, and false otherwise
     *
     * @throws Error
     */
    public function passwordCheck($passwordEncriptado, $algoritmo, $passwordPlano)
    {
        $algoritmo = strtolower($algoritmo);
        switch ($algoritmo) {
            // SSHA crypted passwords
            case 'ssha':
                if (function_exists('hash')) {
                    $hash = base64_decode($passwordEncriptado);
                    // OpenLDAP uses a 4 byte salt, SunDS uses an 8 byte salt - both from char 20.
                    $salt = substr(base64_decode(substr('{SSHA}'.$passwordEncriptado,6)),20);
                    $new_hash = base64_encode(hash('sha1', $passwordPlano.$salt, TRUE ). $salt);
                    if (strcmp($passwordEncriptado, $new_hash) == 0) {
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    throw new Error('La instalación de PHP no tiene la función hash(). No se puede encriptar con SHA.');
                }
                break;
            // Salted MD5
            case 'smd5':
                // Check php mhash support before using it
                if (function_exists('mhash')) {
                    $hash = base64_decode($passwordEncriptado);
                    $salt = substr($hash, 16);
                    $new_hash = base64_encode(mhash(MHASH_MD5, $passwordPlano.$salt).$salt);
                    if (strcmp($passwordEncriptado, $new_hash) == 0) {
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    throw new Error('La instalación de PHP no tiene la función mhash(). No se puede encriptar con SHA.');
                }
                break;
            // SHA crypted passwords
            case 'sha':
                if (strcasecmp($this->passwordHash($passwordPlano, 'sha'), $passwordEncriptado) == 0 || strcasecmp($this->encriptarConSalToba($passwordPlano, 'sha256', $passwordEncriptado), $passwordEncriptado) == 0 || strcasecmp($this->encriptarConSalToba($passwordPlano, 'sha512', $passwordEncriptado), $passwordEncriptado) == 0) {
                    return true;
                } else {
                    return false;
                }
                break;
            // MD5 crypted passwords
            case 'md5':
                if (strcasecmp($this->passwordHash($passwordPlano, 'md5'), $passwordEncriptado) == 0 || strcasecmp(hash($algoritmo, $passwordPlano), $passwordEncriptado) == 0) {
                    return true;
                } else {
                    return false;
                }
                break;
            // Crypt passwords
            case 'crypt':
                if (preg_match('/^\\$2+/', $passwordEncriptado)) { // Check if it's blowfish crypt
                    // Make sure that web server supports blowfish crypt
                    if (!defined('CRYPT_BLOWFISH') || CRYPT_BLOWFISH == 0) {
                        throw new Error('La libreria de encriptación no soporta blowfish.');
                    }
                    if (crypt($passwordPlano, $passwordEncriptado) == $passwordEncriptado) {
                        return true;
                    } else {
                        return false;
                    }
                } elseif (strstr($passwordEncriptado, '$1$')) { // Check if it's an crypted md5
                    // Make sure that web server supports md5 crypt
                    if (!defined('CRYPT_MD5') || CRYPT_MD5 == 0) {
                        throw new Error('La libreria de encriptación no soporta md5crypt.');
                    }
                    list($dummy, $type, $salt, $hash) = explode('$', $passwordEncriptado);
                    if (crypt($passwordPlano, '$1$'.$salt) == $passwordEncriptado) {
                        return true;
                    } else {
                        return false;
                    }
                } elseif (strstr($passwordEncriptado, '_')) { // Check if it's extended des crypt
                    // Make sure that web server supports ext_des
                    if (!defined('CRYPT_EXT_DES') || CRYPT_EXT_DES == 0) {
                        throw new Error('La libreria de encriptación no soporta DES extendido.');
                    }
                    if (crypt($passwordPlano, $passwordEncriptado) == $passwordEncriptado) {
                        return true;
                    } else {
                        return false;
                    }
                } else { // Password is plain crypt
                    if (crypt($passwordPlano, $passwordEncriptado) == $passwordEncriptado) {
                        return true;
                    } else {
                        return false;
                    }
                }
                break;
            case '':
            case 'plano':
                if ($passwordPlano == $passwordEncriptado) {
                    return true;
                } else {
                    return false;
                }
            // No crypt is given assume plaintext passwords are used
            // no break
            default:
                throw new Error('Algoritmo de encriptación no válido. Utilice: crypt, ssha, smd5, md5, sha o plano.');
        }
    }

    /**
     * @param int $length
     *
     * @return string
     */
    public function getRamdomPasswordPlano($length = 15)
    {
        return $this->randomSalt($length);
    }

    /**
     * Used to generate a random salt for crypt-style passwords. Salt strings are used
     * to make pre-built hash cracking dictionaries difficult to use as the hash algorithm uses
     * not only the user's password but also a randomly generated string. The string is
     * stored as the first N characters of the hash for reference of hashing algorithms later.
     *
     * @param int The length of the salt string to generate
     *
     * @return string The generated salt string
     */
    private function randomSalt($length)
    {
        $possible = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./';
        $str = '';
        mt_srand((float) microtime() * 1000000);

        while (strlen($str) < $length) {
            $str .= substr($possible, (rand() % strlen($possible)), 1);
        }

        return $str;
    }

    public function passwordHashToba($passwordPlano, $algoritmo = '')
    {
        if ($algoritmo != 'plano') {
            if ($algoritmo == 'md5') {
                $clave = hash($algoritmo, $passwordPlano);
            } else {
                $clave = $this->encriptarConSalToba($passwordPlano, $algoritmo);
            }
        } else {
            $clave = $passwordPlano;
        }

        return $clave;
    }

    /**
     * @param $clave
     * @param $metodo
     * @param null $sal
     *
     * @return string
     */
    private function encriptarConSalToba($clave, $metodo, $sal = null)
    {
        if (version_compare(PHP_VERSION, '5.3.2') >= 0 || $metodo == 'crypt') {
            $hasher = new Hash($metodo, $this->logger);
            if (is_null($sal)) {                                    //Hash nuevo
                return $hasher->hash($clave);
            } else {                                            //Verificacion
                $resultado = $hasher->getHashVerificador($clave, $sal);
                if (strlen($resultado) > 13) {    //Si es menor a 13 hubo error, puede ser que el hash
                    return $resultado;        //se hubiera generado con el metodo anterior
                }
            }
        }

        if (is_null($sal)) {
            $sal = $this->getSalt();
        } else {
            $sal = substr($sal, 0, 10);
        }

        return $sal.hash($metodo, $sal.$clave);
    }

    /**
     * @return string
     */
    private function getSalt()
    {
        return substr(md5(uniqid(rand(), true)), 0, 10);
    }

    /**
     * Convierte el string a UTF-8 a menos que ya se encuentre en dicho encoding.
     *
     * @param string $s
     *
     * @return string $s en utf8
     */
    public function utf8EncodeSeguro($s)
    {
        if (mb_detect_encoding($s, 'UTF-8', true) == 'UTF-8') {
            return $s;
        }

        return utf8_encode($s);
    }

    /**
     * Convierte a LATIN-1 un string UTF-8, a menos que no este en ese encoding.
     * @param string $s
     * @return string $s en latin1
     */
    function utf8DecodeSeguro($s)
    {
        if (mb_detect_encoding($s, "UTF-8", true) == "UTF-8") {
            return utf8_decode($s);
        }

        return $s;
    }

    /**
     * @param $datos
     *
     * @return array|string
     */
    public function arrayToLatin1($datos)
    {
        if (is_string($datos)) {
            return $this->utf8DecodeSeguro($datos);
        }
        if (!is_array($datos)) {
            return $datos;
        }
        $ret = array();
        foreach ($datos as $i => $d) {
            $ret[$i] = $this->arrayToLatin1($d);
        }

        return $ret;
    }

    public function arrayToUtf8($datos)
    {
        if (is_string($datos)) {
            return $this->utf8EncodeSeguro($datos);
        }
        if (!is_array($datos)) {
            return $datos;
        }
        $ret = array();
        foreach ($datos as $i => $d) {
            $ret[$i] = $this->arrayToUtf8($d);
        }
        return $ret;
    }

    public function quitarCaracteresEspeciales($cadena = '')
    {
        $cadena = utf8_decode($cadena);
        $cadena = strtr($cadena, utf8_decode(self::CADENA_ESPECIALES), self::CADENA_BASICOS);

        return utf8_encode($cadena);
    }

    /**
     * Sanitiza la configuración de Service Providers para SimpleSAMLPHP.
     *
     * Por algún motivo, si configuran un SP con la url que incluya los puertos
     * estándar (80 o 443), el IdP falla en utilizar el SP en cuestión. Si posee
     * puertos específicos no estándar, los deja sin cambios.
     *
     * @param array $sp la cnfiguración de Service Provider
     *
     * @return array el array formateado, sin puertos estándar
     */
    public function sanitizarSpParaIdp($sp)
    {
        foreach ($sp as $key => $value) {
            // tenemos que reemplazar la key
            unset($sp[$key]);
            $key = $this->eliminarPuertoDefault($key);

            if (is_array($value)) {
                $sp[$key] = $this->sanitizarSpParaIdp($value);
            } else {
                $sp[$key] = $this->eliminarPuertoDefault($value);
            }
        }

        return $sp;
    }

    /**
     * Elimina el puerto 80 (para http) y/o el 443 (para https) de una url, lo estandariza.
     *
     * @param string $url nombre o direccion web del recurso
     *
     * @return string la direccion o url sin puertos estándar
     */
    public function eliminarPuertoDefault($url)
    {
        $schema = parse_url($url, PHP_URL_SCHEME);

        if ($schema == 'https') {
            return preg_replace('/:(443)\//', '/', $url);
        } else {
            return preg_replace('/:(80)\//', '/', $url);
        }
    }

    /**
     * Parsea una configuración de instalación y retorna un arreglo
     *
     * La estructura es muy custom, por ahora flexible como para:
     *
     *    - ou=rectorado#El rectorado
     *    - ou=rectorado#El rectorado|ou=extension,ou=fcf
     *
     * @param string $config
     * @return array
     */
    public function getLdapNodosFromConfig($config)
    {
        $nodos = explode('|', $config);

        foreach ($nodos as $value) {

            // ou=rectorado#El rectorado
            $nodo = explode('#', $value, 2);

            $arrNodos[] = [
                'node' => $nodo[0],
                'name' => $nodo[1] ?? $nodo[0],
            ];
        }

        return $arrNodos;
    }

    /**
     * Retorna la representacion de los elementos 'node' solamente
     *
     * @param array $nodos
     * @return array
     */
    public function getLdapNodosAsOU($nodos)
    {
        foreach ($nodos as $value) {
            $ou[] = $value['node'];
        }

        return $ou;
    }

    /**
     * @param $backend
     * @param $namespace
     * @param $defaultLifetime
     * @param array $parameters
     * @return AbstractAdapter
     * @throws \ErrorException
     */
    public function getCacheByBackend($backend, $namespace, $defaultLifetime, $parameters = [])
    {
        switch ($backend) {
            case 'memcached':
                $host = $parameters['host'] ?? null;
                $port = $parameters['port'] ?? null;
                $user = $parameters['username'] ?? null;
                $pass = $parameters['password'] ?? null;

                $server = "";
                if ($host && $port) {
                    $server = "$host:$port";
                } else {
                    throw new \Exception("Datos de conexión a Memcached no válidos: 'host=$host' y 'port=$port'");
                }

                $auth = "";
                if ($user) {
                    $auth = "$user:$pass@";
                }

                $dsn = "memcached://". $auth . $server;

                $client = MemcachedAdapter::createConnection($dsn);

                $cache = new MemcachedAdapter($client, $namespace, $defaultLifetime);

                break;
            case 'apcu':
                $cache = new ApcuAdapter($namespace, $defaultLifetime);
                break;
            case 'array':
                $cache = new ArrayAdapter(
                    $defaultLifetime = 0,
                    $storeSerialized = false
                );
                break;
            case 'redis':
                throw new \Exception('Cache over redis not implemented');
                break;
            default:
            case 'file':
                $tempDir = $parameters['temporal-dir'] ?? null;
                $cache = new FilesystemAdapter($namespace, $defaultLifetime, $tempDir);
                break;
        }

        return $cache;
    }

    public function sanitizarIdentificador($string)
    {
        $string = str_replace(' ', '-', $string);

        return preg_replace('/[^A-Za-z0-9\-]/', '', $string);
    }

    /**
     * Elimina caracteres especiales que pueda tener un loginIdentifier válido
     *
     * @param $identifier
     * @return mixed
     */
    public function sanitizeCacheKey($identifier)
    {
        $translations = ['@' => '', ',' => ''];

        return strtr($identifier, $translations);;
    }
}
