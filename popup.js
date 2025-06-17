let cookiesGuardadas = []; // Guarda las cookies obtenidas del sitio actual
let currentTab = null;     // Guarda la pestaña activa

/**
 * Determina si una cookie es sospechosa o insegura.
 * @param {string} nombre - Nombre de la cookie
 * @param {string} valor - Valor de la cookie
 * @param {object} cookie - Objeto cookie completo
 * @returns {boolean} true si es sospechosa/insegura, false si es segura
 */
function esSospechosa(nombre, valor, cookie) {
    // Palabras clave comunes en cookies sensibles o de autenticación
    const patrones = /token|auth|session|jwt|access|refresh|csrf|secret|key|api|bearer|sid|uid|id|login|password|hash/i;
    // Detecta si el valor parece un JWT (JSON Web Token)
    const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
    // Detecta valores hexadecimales largos (posibles hashes o identificadores)
    const hexRegex = /^[a-f0-9]{32,}$/i;
    // Detecta cadenas largas en base64 (posibles tokens o datos codificados)
    const base64Regex = /^[A-Za-z0-9+/=]{40,}$/;
    // Verifica si la cookie es insegura: 
    // - No es Secure en HTTPS
    // - No es HttpOnly (accesible por JS)
    const esHttps = cookie && cookie.domain && location.protocol === "https:";
    const insegura = (cookie && esHttps && !cookie.secure) || (cookie && !cookie.httpOnly);

    // Devuelve true si cumple alguna condición de sospecha o inseguridad
    return (
        valor.length > 50 ||              // Valor muy largo
        patrones.test(nombre) ||          // Nombre sospechoso
        patrones.test(valor) ||           // Valor sospechoso
        jwtRegex.test(valor) ||           // Valor con formato JWT
        hexRegex.test(valor) ||           // Valor hexadecimal largo
        base64Regex.test(valor) ||        // Valor base64 largo
        insegura                         // Configuración insegura
    );
}

/**
 * Muestra la lista de cookies en el popup.
 * @param {Array} cookies - Lista de cookies a mostrar
 */
function mostrarCookies(cookies) {
  const lista = document.getElementById("cookie-list");
  lista.innerHTML = "";

  cookies.forEach(c => {
    const sospechosa = esSospechosa(c.name, c.value, c); // Analiza cada cookie
    const div = document.createElement("div");
    div.className = "cookie" + (sospechosa ? " sospechosa" : " segura");

    let expira = c.expirationDate
      ? new Date(c.expirationDate * 1000).toLocaleString()
      : "Sesión";

    div.innerHTML = `
      <strong>${c.name}</strong><br>
      Valor: <code>${c.value}</code><br>
      Dominio: ${c.domain}<br>
      Secure: ${c.secure}<br>
      HttpOnly: ${c.httpOnly}<br>
      Expira: ${expira}<br>
    `;

    // Si es sospechosa, agrega botón para eliminarla
    if (sospechosa) {
      const btn = document.createElement("button");
      btn.textContent = "Eliminar";
      btn.onclick = () => eliminarCookie(c);
      div.appendChild(btn);
    }

    lista.appendChild(div);
  });

  if (cookies.length === 0) {
    lista.textContent = "No hay cookies disponibles.";
  }
}

/**
 * Elimina una cookie específica del sitio actual.
 * @param {object} cookie - Objeto cookie a eliminar
 */
function eliminarCookie(cookie) {
  chrome.cookies.remove({
    url: (cookie.secure ? "https://" : "http://") + cookie.domain.replace(/^\./, ""),
    name: cookie.name
  }, () => {
    console.log("Eliminada:", cookie.name);
    cargarCookies(); // Recarga la lista después de eliminar
  });
}

/**
 * Carga todas las cookies del sitio actual y las muestra.
 */
function cargarCookies() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    currentTab = tabs[0];
    chrome.cookies.getAll({ url: currentTab.url }, (cookies) => {
      cookiesGuardadas = cookies;
      mostrarCookies(cookies);
    });
  });
}

// Elimina solo las cookies sospechosas
document.getElementById("eliminar-sospechosas").addEventListener("click", () => {
  cookiesGuardadas.forEach(c => {
    if (esSospechosa(c.name, c.value, c)) eliminarCookie(c);
  });
});

// Elimina todas las cookies del sitio
document.getElementById("eliminar-todas").addEventListener("click", () => {
  cookiesGuardadas.forEach(c => eliminarCookie(c));
});

// Carga las cookies al abrir el popup
cargarCookies();