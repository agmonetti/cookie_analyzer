let cookiesGuardadas = [];
let currentTab = null;

/**
 * Devuelve un array con los motivos por los que una cookie es sospechosa/insegura.
 * @param {string} nombre - Nombre de la cookie
 * @param {string} valor - Valor de la cookie
 * @param {object} cookie - Objeto cookie completo
 * @returns {Array<string>} Motivos de sospecha
 */
function motivosSospecha(nombre, valor, cookie) {
    const motivos = [];
    const patrones = /token|auth|session|jwt|access|refresh|csrf|secret|key|api|bearer|sid|uid|id|login|password|hash/i;
    const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
    const hexRegex = /^[a-f0-9]{32,}$/i;
    const base64Regex = /^[A-Za-z0-9+/=]{40,}$/;
    const esHttps = cookie && cookie.domain && location.protocol === "https:";
    if (valor.length > 50) motivos.push("Valor muy largo");
    if (patrones.test(nombre)) motivos.push("Nombre sospechoso");
    if (patrones.test(valor)) motivos.push("Valor sospechoso");
    if (jwtRegex.test(valor)) motivos.push("Valor con formato JWT");
    if (hexRegex.test(valor)) motivos.push("Valor hexadecimal largo");
    if (base64Regex.test(valor)) motivos.push("Valor base64 largo");
    if (cookie && esHttps && !cookie.secure) motivos.push("No es Secure en HTTPS");
    return motivos;
}

/**
 * Determina si una cookie es sospechosa/insegura.
 */
function esSospechosa(nombre, valor, cookie) {
    return motivosSospecha(nombre, valor, cookie).length > 0;
}

function mostrarCookies(cookies) {
  const lista = document.getElementById("cookie-list");
  lista.innerHTML = "";

  cookies.forEach(c => {
    const motivos = motivosSospecha(c.name, c.value, c);
    const sospechosa = motivos.length > 0;
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

    // Si es sospechosa, muestra los motivos
    if (sospechosa) {
      const ul = document.createElement("ul");
      ul.style.margin = "6px 0";
      ul.style.paddingLeft = "18px";
      ul.style.fontSize = "12px";
      motivos.forEach(m => {
        const li = document.createElement("li");
        li.textContent = m;
        ul.appendChild(li);
      });
      div.appendChild(ul);

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