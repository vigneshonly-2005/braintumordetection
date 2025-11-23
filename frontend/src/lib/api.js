import API_URL from '../config';


export async function post(path, body, token) {
const res = await fetch(`${API_URL}${path}`, {
method: 'POST',
headers: {
'Content-Type': 'application/json',
...(token ? { Authorization: `Bearer ${token}` } : {})
},
body: JSON.stringify(body)
});
const data = await res.json().catch(() => null);
if (!res.ok) throw { status: res.status, data };
return data;
}


export async function get(path, token) {
const res = await fetch(`${API_URL}${path}`, {
headers: {
...(token ? { Authorization: `Bearer ${token}` } : {})
}
});
const data = await res.json().catch(() => null);
if (!res.ok) throw { status: res.status, data };
return data;
}