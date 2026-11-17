// Управление обходом загружается по открытию раздела; фонового опроса нет.
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const panel = byId('bypass-panel'), edit = byId('bypass-edit'), deletion = byId('bypass-delete');
  let snapshot = null, busy = false, editingID = null, deletingID = null, generation = 0;
  let devices = [], chosen = new Map();
  const node = (tag, text, className) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (className) e.className = className; return e; };
  const message = (id, value) => { byId(id).textContent = value || ''; };
  function controls() {
    for (const root of [panel, edit, deletion]) for (const el of root.querySelectorAll('button,input,select,textarea')) el.disabled = busy;
    byId('bypass-add').disabled = busy || !snapshot?.available;
    byId('bypass-ports').disabled = busy || byId('bypass-network').value === 'all';
    byId('bypass-device-fields').classList.toggle('hidden', byId('bypass-scope').value !== 'devices');
  }
  async function request(path, body) {
    const response = await fetch(path, body === undefined ? { cache: 'no-store' } : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const result = await response.json();
    if (response.status === 401) { reset(); throw Error('Сессия истекла. Войдите снова.'); }
    if (!response.ok) throw Error(result.error || 'Не удалось применить правила');
    return result;
  }
  function render() {
    const root = byId('bypass-rules'); root.replaceChildren();
    if (!snapshot) { controls(); return; }
    message('bypass-status', !snapshot.available ? 'Управление обходом доступно на роутере с Linux/Entware.' : snapshot.active ? 'Правила применены · ' + new Date(snapshot.applied * 1000).toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' }) : snapshot.configured ? 'Настройки сохранены; применение не подтверждено.' : 'Правил пока нет. Добавьте сервисы, которые должны идти напрямую.');
    message('bypass-error', snapshot.error || '');
    for (const rule of snapshot.rules) {
      const card = node('article', undefined, 'bypass-rule');
      const heading = node('div', undefined, 'bypass-rule-heading');
      heading.append(node('h3', rule.name), node('span', rule.enabled ? 'Включено' : 'Выключено', 'bypass-rule-state' + (rule.enabled ? '' : ' off')));
      card.append(heading);
      const network = rule.network === 'all' ? 'Все протоколы' : rule.network.toUpperCase();
      card.append(node('p', network + (rule.ports ? ' · порты ' + rule.ports : ' · все порты'), 'bypass-rule-meta'));
      card.append(node('p', rule.scope === 'all' ? 'Все устройства домашней сети' : rule.devices.map(d => (d.name || d.mac) + ' (' + d.mac + ')').join(' · '), 'bypass-rule-meta'));
      const addresses = node('details'); addresses.append(node('summary', 'Адреса и подсети: ' + rule.destinations.length), node('pre', rule.destinations.join('\n'))); card.append(addresses);
      const actions = node('div', undefined, 'links');
      const toggle = node('button', rule.enabled ? 'Выключить' : 'Включить'); toggle.type = 'button';
      toggle.addEventListener('click', () => mutate(snapshot.rules.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r)));
      const change = node('button', 'Изменить'); change.type = 'button'; change.addEventListener('click', () => openEditor(rule));
      const remove = node('button', 'Удалить', 'danger'); remove.type = 'button'; remove.addEventListener('click', () => { deletingID = rule.id; message('bypass-delete-name', rule.name); message('bypass-delete-error', ''); deletion.showModal(); });
      actions.append(toggle, change, remove); card.append(actions); root.append(card);
    }
    controls();
  }
  async function load() {
    if (busy) return; busy = true; controls(); message('bypass-error', '');
    const currentGeneration = generation;
    try { const result = await request('/api/bypass'); if (currentGeneration !== generation) return; snapshot = result; render(); }
    catch (err) { message('bypass-error', err.message); }
    finally { busy = false; controls(); }
  }
  async function mutate(rules, errorID = 'bypass-error') {
    if (busy || !snapshot?.available) return false;
    busy = true; controls(); message(errorID, '');
    const currentGeneration = generation;
    try { const result = await request('/api/bypass', { revision: snapshot.revision, rules }); if (currentGeneration !== generation) return false; snapshot = result; render(); return true; }
    catch (err) { message(errorID, err.message); return false; }
    finally { busy = false; controls(); }
  }
  function renderDevices() {
    const merged = new Map(devices.map(d => [d.mac.toLowerCase(), { ...d, online: d.online === true }]));
    for (const [mac, saved] of chosen) merged.set(mac, { ...merged.get(mac), ...saved });
    const root = byId('bypass-devices'); root.replaceChildren();
    const list = [...merged.values()].sort((a, b) => (a.name || a.mac).localeCompare(b.name || b.mac, 'ru'));
    for (const device of list) {
      const mac = device.mac.toLowerCase(), label = node('label', undefined, 'bypass-device'), checkbox = node('input');
      checkbox.type = 'checkbox'; checkbox.checked = chosen.has(mac); checkbox.value = mac;
      checkbox.addEventListener('change', () => { if (checkbox.checked) chosen.set(mac, { mac, name: device.name || mac }); else chosen.delete(mac); });
      const text = node('span', device.name || mac);
      text.append(node('small', mac + (device.ip ? ' · ' + device.ip : '') + (device.online === false ? ' · сейчас не в сети' : '')));
      label.append(checkbox, text); root.append(label);
    }
    controls();
  }
  function openEditor(rule) {
    const currentGeneration = ++generation;
    editingID = rule?.id || null;
    const templates = byId('bypass-template');
    templates.replaceChildren(node('option', 'Выбрать шаблон…'));
    templates.children[0].value = '';
    for (const template of snapshot?.templates || []) {
      const option = node('option', template.name); option.value = template.id; templates.append(option);
    }
    templates.value = '';
    message('bypass-template-info', 'Шаблон заполнит название, адреса, протокол и порты. Перед сохранением их можно изменить.' + (rule ? ' Выбор устройств и включённость сохранятся.' : ''));
    message('bypass-edit-title', rule ? 'Изменить правило обхода' : 'Новое правило обхода');
    byId('bypass-name').value = rule?.name || '';
    byId('bypass-enabled').checked = rule?.enabled ?? true;
    byId('bypass-network').value = rule?.network || 'all';
    byId('bypass-ports').value = rule?.ports || '';
    byId('bypass-addresses').value = (rule?.destinations || []).join('\n');
    byId('bypass-scope').value = rule?.scope || 'all';
    byId('bypass-device-name').value = ''; byId('bypass-device-mac').value = '';
    chosen = new Map((rule?.devices || []).map(d => [d.mac.toLowerCase(), { mac: d.mac.toLowerCase(), name: d.name }]));
    devices = [...new Map((snapshot?.rules || []).flatMap(r => r.devices).map(d => [d.mac.toLowerCase(), d])).values()];
    message('bypass-edit-error', ''); message('bypass-devices-status', 'Получаю список устройств…');
    renderDevices(); edit.showModal(); controls();
    request('/api/bypass/devices').then(result => {
      if (generation !== currentGeneration || !edit.open) return;
      devices = result.devices; message('bypass-devices-status', 'Сохранённый MAC продолжает действовать после смены IP.'); renderDevices();
    }).catch(err => { if (generation === currentGeneration && edit.open) message('bypass-devices-status', err.message); });
  }
  byId('bypass-template').addEventListener('change', () => {
    const template = snapshot?.templates?.find(t => t.id === byId('bypass-template').value);
    if (!template) { message('bypass-template-info', 'Поля можно заполнить или изменить вручную.'); return; }
    byId('bypass-name').value = template.name;
    byId('bypass-network').value = template.network;
    byId('bypass-ports').value = template.ports;
    byId('bypass-addresses').value = template.destinations.join('\n');
    if (!editingID) byId('bypass-scope').value = template.scope;
    const date = template.updated.split('-').reverse().join('.');
    message('bypass-template-info', template.description + ' Список от ' + date + ' · адресов и подсетей: ' + template.destinations.length + '. Применится после сохранения.');
    message('bypass-edit-error', ''); controls();
  });
  byId('bypass-device-add').addEventListener('click', () => {
    const mac = byId('bypass-device-mac').value.trim().toLowerCase().replaceAll('-', ':');
    const name = byId('bypass-device-name').value.trim() || mac;
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) { message('bypass-edit-error', 'Введите MAC в формате AA:BB:CC:DD:EE:FF'); return; }
    chosen.set(mac, { mac, name }); message('bypass-edit-error', ''); renderDevices();
    byId('bypass-device-mac').value = ''; byId('bypass-device-name').value = '';
  });
  byId('bypass-form').addEventListener('submit', async event => {
    event.preventDefault(); if (!snapshot) return;
    const scope = byId('bypass-scope').value;
    if (scope === 'devices' && !chosen.size) { message('bypass-edit-error', 'Выберите хотя бы одно устройство или вариант «Все устройства».'); return; }
    const rule = { id: editingID || 'rule-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8), name: byId('bypass-name').value.trim(), enabled: byId('bypass-enabled').checked,
      network: byId('bypass-network').value, ports: byId('bypass-network').value === 'all' ? '' : byId('bypass-ports').value.trim(), scope,
      destinations: byId('bypass-addresses').value.split(/[\s,;]+/).filter(Boolean), devices: scope === 'all' ? [] : [...chosen.values()] };
    const rules = editingID ? snapshot.rules.map(r => r.id === editingID ? rule : r) : [...snapshot.rules, rule];
    if (await mutate(rules, 'bypass-edit-error')) edit.close();
  });
  byId('bypass-delete-confirm').addEventListener('click', async () => { if (await mutate(snapshot.rules.filter(r => r.id !== deletingID), 'bypass-delete-error')) deletion.close(); });
  byId('bypass-network').addEventListener('change', controls); byId('bypass-scope').addEventListener('change', controls);
  byId('bypass-refresh').addEventListener('click', load); byId('bypass-add').addEventListener('click', () => openEditor(null));
  byId('bypass-cancel').addEventListener('click', () => edit.close()); byId('bypass-delete-cancel').addEventListener('click', () => deletion.close());
  for (const dialog of [edit, deletion]) dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  panel.addEventListener('toggle', () => { if (panel.open && !snapshot && !byId('dashboard').classList.contains('hidden')) load(); });
  document.addEventListener('vpn-auth-ready', () => { if (panel.open && !snapshot) load(); });
  function reset() { generation++; snapshot = null; devices = []; chosen = new Map(); byId('bypass-rules').replaceChildren(); if (edit.open) edit.close(); if (deletion.open) deletion.close(); message('bypass-status', 'Войдите для управления правилами.'); controls(); }
  document.addEventListener('vpn-auth-lost', reset);
  controls();
})();
