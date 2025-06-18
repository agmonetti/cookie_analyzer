let cookiesGuardadas = [];
let currentTab = null;

/**
 * Base de datos de cookies conocidas como maliciosas o de tracking
 */
const cookiesConocidas = {
    maliciosas: [
        '_ga', '_gid', '_gat', '_gtag', '_fbp', '_fbc', 'fr', 'doubleclick',
        '_hjid', '_hjFirstSeen', '_hjIncludedInSessionSample', 'hotjar',
        'amplitude', 'mixpanel', 'segment', 'intercom', 'drift',
        '__utma', '__utmb', '__utmc', '__utmz', '__utmt',
        'yandex_metrica', 'ya_metrica', '_ym_', '_yasc',
        'optimizely', 'vwo_uuid', 'ab_test', 'split_test'
    ],
    seguimiento: [
        '_dc_gtm', '_gcl_', '_gac_', 'ads', 'adnxs', 'doubleclick',
        'facebook', 'linkedin', 'twitter', 'pinterest'
    ],
    fingerprinting: [
        'canvas_fp', 'webgl_fp', 'audio_fp', 'font_fp', 'screen_fp'
    ]
};

/**
 * Patrones de empresas de tracking conocidas
 */
const dominiosTracking = [
    'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
    'facebook.com', 'connect.facebook.net', 'hotjar.com',
    'mixpanel.com', 'segment.com', 'amplitude.com',
    'yandex.ru', 'mc.yandex.ru', 'optimizely.com'
];

/**
 * Detecta cookies de fingerprinting basándose en patrones avanzados
 */
function esFingerprinting(nombre, valor, cookie) {
    const fingerprintPatterns = [
        /canvas|webgl|audio|font|screen|timezone|language|plugins/i,
        /fp_|fingerprint|device_id|browser_id/i,
        /^[a-f0-9]{16,64}$/i // Hash de características del dispositivo
    ];
    
    return fingerprintPatterns.some(pattern => 
        pattern.test(nombre) || pattern.test(valor)
    );
}

/**
 * Detecta cookies de tracking basándose en dominios y nombres conocidos
 */
function esTracking(nombre, valor, cookie) {
    const trackingPatterns = [
        /^_ga|_gid|_gat|_gtag|_utm|__utm/i,
        /facebook|fb_|_fbp|_fbc/i,
        /doubleclick|googlesyndication/i,
        /hotjar|mixpanel|segment|amplitude/i
    ];
    
    // Verificar si la cookie pertenece a un dominio de tracking conocido
    const dominioTracking = dominiosTracking.some(dominio => 
        cookie.domain.includes(dominio)
    );
    
    // Verificar patrones en el nombre
    const patronTracking = trackingPatterns.some(pattern => 
        pattern.test(nombre) || pattern.test(valor)
    );
    
    return dominioTracking || patronTracking || cookiesConocidas.maliciosas.includes(nombre);
}

/**
 * Detecta cookies de terceros (cross-site)
 */
function esTerceros(cookie, urlActual) {
    if (!urlActual || !cookie.domain) return false;
    
    try {
        const dominioActual = new URL(urlActual).hostname;
        const dominioLimpio = dominioActual.replace(/^www\./, '');
        const cookieDominio = cookie.domain.replace(/^\./, '').replace(/^www\./, '');
        
        return !cookieDominio.includes(dominioLimpio) && !dominioLimpio.includes(cookieDominio);
    } catch (e) {
        return false;
    }
}

/**
 * Analiza la entropía del valor (detecta valores aleatorios/cifrados)
 */
function tieneAltaEntropia(valor) {
    if (valor.length < 10) return false;
    
    const charCounts = {};
    for (let char of valor) {
        charCounts[char] = (charCounts[char] || 0) + 1;
    }
    
    let entropy = 0;
    const len = valor.length;
    for (let count of Object.values(charCounts)) {
        const probability = count / len;
        entropy -= probability * Math.log2(probability);
    }
    
    return entropy > 4; // Alta entropía indica valor aleatorio/cifrado
}

/**
 * Calcula el nivel de riesgo de una cookie (0-100)
 */
function calcularRiesgo(nombre, valor, cookie) {
    let riesgo = 0;
    
    // Patrones de seguridad críticos - MOVIDO AL PRINCIPIO
    const patrones = /token|auth|session|jwt|access|refresh|csrf|secret|key|api|bearer|sid|uid|login|password|hash/i;
    const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
    const hexRegex = /^[a-f0-9]{32,}$/i;
    const base64Regex = /^[A-Za-z0-9+/=]{40,}$/;
    const esHttps = currentTab?.url?.startsWith('https:');
    
    // RIESGOS CRÍTICOS DE SEGURIDAD (mayor puntuación)
    if (patrones.test(nombre)) riesgo += 35; // Nombre relacionado con autenticación
    if (patrones.test(valor)) riesgo += 30; // Valor relacionado con autenticación
    if (jwtRegex.test(valor)) riesgo += 40; // Token JWT detectado
    if (hexRegex.test(valor)) riesgo += 25; // Hash hexadecimal largo
    if (base64Regex.test(valor)) riesgo += 25; // Cadena base64 larga
    
    // Configuración de seguridad insegura para cookies sensibles
    if (patrones.test(nombre) || patrones.test(valor)) {
        if (!cookie.httpOnly) riesgo += 25; // Cookie sensible accesible desde JavaScript
        if (!cookie.secure && (esHttps || currentTab?.url?.includes('localhost'))) riesgo += 20; // Cookie sensible sin Secure
        if (!cookie.sameSite || cookie.sameSite === 'none') riesgo += 20; // Cookie sensible sin SameSite
    } else {
        // Para cookies no sensibles, menor penalización
        if (!cookie.httpOnly) riesgo += 10;
        if (!cookie.secure && esHttps) riesgo += 8;
        if (!cookie.sameSite || cookie.sameSite === 'none') riesgo += 8;
    }
    
    // Cookies de tracking conocidas
    if (cookiesConocidas.maliciosas.includes(nombre)) riesgo += 40;
    if (esTracking(nombre, valor, cookie)) riesgo += 35;
    if (esFingerprinting(nombre, valor, cookie)) riesgo += 45;
    if (esTerceros(cookie, currentTab?.url)) riesgo += 25;
    
    // Características sospechosas adicionales
    if (valor.length > 100) riesgo += 15;
    if (tieneAltaEntropia(valor)) riesgo += 20;
    
    // Patrones maliciosos extremos
    const patronesMaliciosos = /malware|virus|exploit|xss|injection|backdoor/i;
    if (patronesMaliciosos.test(nombre) || patronesMaliciosos.test(valor)) riesgo += 80;
    
    return Math.min(riesgo, 100);
}

/**
 * Devuelve un array con los motivos por los que una cookie es sospechosa/insegura.
 */
function motivosSospecha(nombre, valor, cookie) {
    const motivos = [];
    
    // Patrones de seguridad críticos
    const patrones = /token|auth|session|jwt|access|refresh|csrf|secret|key|api|bearer|sid|uid|login|password|hash/i;
    const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
    const hexRegex = /^[a-f0-9]{32,}$/i;
    const base64Regex = /^[A-Za-z0-9+/=]{40,}$/;
    const esHttps = currentTab?.url?.startsWith('https:');
    const esLocalhost = currentTab?.url?.includes('localhost') || currentTab?.url?.includes('127.0.0.1');
    
    // Detectar si es una cookie sensible
    const esCookieSensible = patrones.test(nombre) || patrones.test(valor);
    
    // Categorización por tipo
    if (cookiesConocidas.maliciosas.includes(nombre)) {
        motivos.push("Cookie de tracking conocida");
    }
    
    if (esTracking(nombre, valor, cookie)) {
        motivos.push("Cookie de seguimiento/analytics");
    }
    
    if (esFingerprinting(nombre, valor, cookie)) {
        motivos.push("Posible fingerprinting del dispositivo");
    }
    
    if (esTerceros(cookie, currentTab?.url)) {
        motivos.push("Cookie de terceros (cross-site)");
    }
    
    if (tieneAltaEntropia(valor)) {
        motivos.push("Valor con alta entropía (posiblemente cifrado)");
    }
    
    // Análisis de seguridad mejorado
    if (valor.length > 100) motivos.push("Valor extremadamente largo");
    if (patrones.test(nombre)) motivos.push("⚠️ CRÍTICO: Nombre relacionado con autenticación/sesión");
    if (patrones.test(valor)) motivos.push("⚠️ CRÍTICO: Valor relacionado con autenticación");
    if (jwtRegex.test(valor)) motivos.push("🔴 CRÍTICO: Token JWT detectado");
    if (hexRegex.test(valor)) motivos.push("Hash hexadecimal largo");
    if (base64Regex.test(valor)) motivos.push("Cadena base64 larga");
    
    // Configuración de seguridad - más estricto para cookies sensibles
    if (esCookieSensible) {
        if (!cookie.httpOnly) motivos.push("🔴 CRÍTICO: Cookie sensible accesible desde JavaScript (riesgo XSS)");
        if (!cookie.secure && (esHttps || esLocalhost)) motivos.push("🔴 CRÍTICO: Cookie sensible sin flag Secure");
        if (!cookie.sameSite || cookie.sameSite === 'none') motivos.push("🔴 CRÍTICO: Cookie sensible sin protección SameSite (riesgo CSRF)");
    } else {
        if (!cookie.httpOnly) motivos.push("Sin flag HttpOnly (accesible desde JavaScript)");
        if (!cookie.secure && esHttps) motivos.push("Sin flag Secure en sitio HTTPS");
        if (!cookie.sameSite || cookie.sameSite === 'none') motivos.push("Sin protección SameSite");
    }
    
    const riesgo = calcularRiesgo(nombre, valor, cookie);
    return { motivos, riesgo };
}

/**
 * Determina si una cookie es sospechosa/insegura.
 */
function esSospechosa(nombre, valor, cookie) {
    const { riesgo } = motivosSospecha(nombre, valor, cookie);
    return riesgo >= 30; // Cambiado: >= 30 para ser consistente
}
/**
 * Obtiene el color basado en el nivel de riesgo
 */
function obtenerColorRiesgo(riesgo) {
    if (riesgo >= 70) return 'critica';
    if (riesgo >= 50) return 'alta';
    if (riesgo >= 30) return 'media';
    return 'baja';
}

// Función principal para cargar cookies
async function cargarCookies() {
  try {
    // Obtener la pestaña activa
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab;
    
    if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('moz-extension://')) {
      document.getElementById("cookie-list").innerHTML = 
        "<div class='no-cookies'>No se pueden analizar cookies en páginas internas del navegador.</div>";
      return;
    }

    // Obtener cookies del sitio actual
    const url = new URL(tab.url);
    const cookies = await chrome.cookies.getAll({ domain: url.hostname });
    
    cookiesGuardadas = cookies;
    mostrarCookies(cookies);
  } catch (error) {
    console.error('Error cargando cookies:', error);
    document.getElementById("cookie-list").innerHTML = 
      "<div class='no-cookies'>Error cargando cookies: " + error.message + "</div>";
  }
}

function mostrarCookies(cookies) {
  const lista = document.getElementById("cookie-list");
  lista.innerHTML = "";

  // Ordenar cookies por nivel de riesgo (mayor riesgo primero)
  const cookiesOrdenadas = cookies.sort((a, b) => {
    const riesgoA = calcularRiesgo(a.name, a.value, a);
    const riesgoB = calcularRiesgo(b.name, b.value, b);
    return riesgoB - riesgoA;
  });

  cookiesOrdenadas.forEach(c => {
    const { motivos, riesgo } = motivosSospecha(c.name, c.value, c);
    const sospechosa = riesgo >= 30; // Cambiado: >= 30 es sospechosa
    const nivelRiesgo = obtenerColorRiesgo(riesgo);
    
    const div = document.createElement("div");
    // CORRECCIÓN: Si el riesgo es < 30, usar 'segura', sino usar el nivel de riesgo
    div.className = `cookie ${riesgo < 30 ? 'segura' : nivelRiesgo}`;

    let expira = c.expirationDate
      ? new Date(c.expirationDate * 1000).toLocaleString()
      : "Sesión";

    // Truncar valor si es muy largo
    const valorMostrado = c.value.length > 50 
      ? c.value.substring(0, 50) + '...' 
      : c.value;

    div.innerHTML = `
      <div class="cookie-header">
        <strong>${c.name}</strong>
        <span class="riesgo-badge riesgo-${nivelRiesgo}">Riesgo: ${riesgo}%</span>
      </div>
      <div class="cookie-details">
        <strong>Valor:</strong> <code title="${c.value}">${valorMostrado}</code><br>
        <strong>Dominio:</strong> ${c.domain}<br>
        <strong>Seguridad:</strong> Secure: ${c.secure ? '✓' : '✗'}, HttpOnly: ${c.httpOnly ? '✓' : '✗'}, SameSite: ${c.sameSite || 'None'}<br>
        <strong>Expira:</strong> ${expira}
      </div>
    `;

    // Solo mostrar motivos y botón eliminar si es sospechosa (riesgo >= 30)
    if (sospechosa && motivos.length > 0) {
      const motivosDiv = document.createElement("div");
      motivosDiv.className = "motivos-sospecha";
      motivosDiv.innerHTML = "<strong>⚠️ Motivos de alerta:</strong>";
      
      const ul = document.createElement("ul");
      motivos.forEach(m => {
        const li = document.createElement("li");
        li.textContent = m;
        ul.appendChild(li);
      });
      motivosDiv.appendChild(ul);
      div.appendChild(motivosDiv);

      const btn = document.createElement("button");
      btn.textContent = "🗑️ Eliminar";
      btn.className = "btn-eliminar";
      btn.onclick = () => eliminarCookie(c);
      div.appendChild(btn);
    }

    lista.appendChild(div);
  });

  if (cookies.length === 0) {
    lista.innerHTML = "<div class='no-cookies'>No hay cookies disponibles.</div>";
  }

  // Mostrar resumen de riesgos
  mostrarResumenRiesgos(cookies);
}


/**
 * Muestra un resumen de los riesgos encontrados
 */
function mostrarResumenRiesgos(cookies) {
  const resumen = document.getElementById("resumen-riesgos") || document.createElement("div");
  resumen.id = "resumen-riesgos";
  resumen.className = "resumen-riesgos";

  const stats = {
    total: cookies.length,
    criticas: 0,
    altas: 0,
    medias: 0,
    bajas: 0,
    seguras: 0
  };

  cookies.forEach(c => {
    const riesgo = calcularRiesgo(c.name, c.value, c);
    
    // CORRECCIÓN: Las cookies con riesgo < 30 se consideran seguras
    if (riesgo < 30) {
      stats.seguras++;
    } else if (riesgo >= 70) {
      stats.criticas++;
    } else if (riesgo >= 50) {
      stats.altas++;
    } else if (riesgo >= 30) {
      stats.medias++;
    }
  });

  resumen.innerHTML = `
    <h3>📊 Resumen de Análisis</h3>
    <div class="stats-grid">
      <div class="stat critica">Críticas: ${stats.criticas}</div>
      <div class="stat alta">Altas: ${stats.altas}</div>
      <div class="stat media">Medias: ${stats.medias}</div>
      <div class="stat segura">Seguras: ${stats.seguras}</div>
    </div>
  `;

  if (!document.getElementById("resumen-riesgos")) {
    document.getElementById("cookie-list").parentNode.insertBefore(resumen, document.getElementById("cookie-list"));
  }
}

// Función para eliminar una cookie específica
async function eliminarCookie(cookie) {
  try {
    await chrome.cookies.remove({
      url: `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`,
      name: cookie.name
    });
    
    // Recargar la lista
    cargarCookies();
  } catch (error) {
    console.error('Error eliminando cookie:', error);
    alert('Error al eliminar la cookie: ' + error.message);
  }
}

// Función para eliminar cookies sospechosas
async function eliminarSospechosas() {
  if (!cookiesGuardadas || cookiesGuardadas.length === 0) {
    alert('No hay cookies para analizar');
    return;
  }

  const sospechosas = cookiesGuardadas.filter(c => esSospechosa(c.name, c.value, c));
  
  if (sospechosas.length === 0) {
    alert('No se encontraron cookies sospechosas');
    return;
  }

  if (confirm(`¿Eliminar ${sospechosas.length} cookies sospechosas?`)) {
    try {
      for (const cookie of sospechosas) {
        await chrome.cookies.remove({
          url: `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`,
          name: cookie.name
        });
      }
      cargarCookies();
    } catch (error) {
      console.error('Error eliminando cookies:', error);
      alert('Error al eliminar cookies: ' + error.message);
    }
  }
}

// Función para eliminar todas las cookies
async function eliminarTodas() {
  if (!currentTab) {
    alert('No se pudo obtener información de la pestaña actual');
    return;
  }

  try {
    const url = new URL(currentTab.url);
    const cookies = await chrome.cookies.getAll({ domain: url.hostname });
    
    if (cookies.length === 0) {
      alert('No hay cookies para eliminar');
      return;
    }

    if (confirm(`¿Eliminar TODAS las ${cookies.length} cookies del sitio ${url.hostname}?`)) {
      for (const cookie of cookies) {
        await chrome.cookies.remove({
          url: `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`,
          name: cookie.name
        });
      }
      cargarCookies();
    }
  } catch (error) {
    console.error('Error eliminando todas las cookies:', error);
    alert('Error al eliminar cookies: ' + error.message);
  }
}

// Event listeners para los botones
document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('eliminar-sospechosas').addEventListener('click', eliminarSospechosas);
  document.getElementById('eliminar-todas').addEventListener('click', eliminarTodas);
  
  // Cargar cookies al iniciar
  cargarCookies();
});