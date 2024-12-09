const express = require('express');
const app = express();
const ejs = require('ejs');
const session = require('express-session');
const path = require("path");
const port = 8080
const config = require("./config");
const { Database } = require("nukleon");
const crypto = require("crypto");
const fs = require("fs");
const axios = require("axios");

app.set('view engine', 'ejs');
app.use(express.static('views'))
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'angbotkey',
  resave: false,
  saveUninitialized: true
}));
app.use(express.json());

app.get('/', (req, res) => {
  if (!req.session.durum) return res.render('index', {"data": ""});
  const db = new Database("./database/userwebhook.json");
  let data = "";
  if(!db.get(req.session.username)) return res.render('index', {"data": ""});
  db.get(req.session.username).forEach(value => {
    data += `<div class="wrapper-row">
  <div class="row-column">${value.webhookurl}</div>
  <div class="row-column">https://${config.domain}/api/webhooks/${value.id}</div>
  <div class="row-column">${value.ip}</div>
  <div class="row-column"><button number="${value.id}" id="delete" class="btn v-100 btn-danger delete">Sil</button></div>
</div>` + "\n";
  });
  res.render('index', {"data": data})
})

app.get("/:page", (req, res) => {
  const page = req.params.page;
  if(page === "login") {
    res.sendFile(path.join(__dirname, "views", `${page}.html`));
  } else if(page === "register") {
    res.sendFile(path.join(__dirname, "views", `${page}/index.html`));
  }
});

app.post("/api/webhooks/:id", async (req, res) => {
  const id = req.params.id;
  const db = new Database("./database/webhook.json");
  const ip = req.headers['cf-connecting-ip'] || req.headers["x-reval-ip"] || req.headers["x-forwarded-for"] || req.socket.remoteAddress || undefined;
  console.log(ip)
  console.log(id)
  if(db.get(id)) {
    if(db.get(id).ip != ip) return res.status(403);
    const targetUrl = db.get(id).webhookurl; // Verilerin yönlendirileceği URL

    try {
        // Gelen veriyi al
        const incomingData = req.body;
        console.log(req.body)

        // Axios ile başka bir URL'ye yönlendir
        const response = await axios.post(targetUrl, incomingData, {
            headers: req.headers // Orijinal başlıkları da göndermek için
        });

        // Başarılı yanıt döner
        console.log(response)
        res.status(response.status).send(response.data);
    } catch (error) {
        // Hata yanıtı döner
        console.log(error)
        res.status(error.response?.status || 500).send(error.response?.data || 'Bir hata oluştu');
    }
  }
})

app.get("/api/webhooks/:id", async (req, res) => {
  const id = req.params.id;
  const db = new Database("./database/webhook.json");
  const ip = req.headers['cf-connecting-ip'] || req.headers["x-reval-ip"] || req.headers["x-forwarded-for"] || req.socket.remoteAddress || undefined;
  console.log(ip)
  console.log(id)
  if (db.get(id)) {
    if (db.get(id).ip != ip) return res.status(403).send("IP adresi eşleşmiyor");
    
    const targetUrl = db.get(id).webhookurl; // Verilerin yönlendirileceği URL

    try {
      // Gelen veriyi query üzerinden al
      const incomingData = req.query;
      console.log(req.query)

      // Axios ile başka bir URL'ye yönlendir
      const response = await axios.get(targetUrl, {
        params: incomingData, // Sorgu parametrelerini yönlendirme için ekler
        headers: req.headers // Orijinal başlıkları da göndermek için
      });

      // Başarılı yanıt döner
      console.log(response)
      res.status(response.status).send(response.data);
    } catch (error) {
      // Hata yanıtı döner
      console.log(error)
      res.status(error.response?.status || 500).send(error.response?.data || 'Bir hata oluştu');
    }
  } else {
    res.status(404).send("ID bulunamadı");
  }
})

app.post("/api/check", async(req, res) => {
  if (!req.session.durum) return res.send({"status": true, "link": "./login"});
  res.send({"status": false})
})

app.get("/api/checkip", async(req, res) => {
  const ip = req.headers['cf-connecting-ip'] || req.headers["x-reval-ip"] || req.headers["x-forwarded-for"] || req.socket.remoteAddress || undefined;
  res.send(ip)
})

app.post("/api/webhook", async(req, res) => {
  const db = new Database("./database/webhook.json");
  const dbuser = new Database("./database/userwebhook.json");
  if(!req.session.durum) return res.send({"status": false, "message": "Please Log In Again!"});
  if(!isDiscordWebhook(req.body.webhookurl)) return res.send({"status": false, "message": "Please Enter Correct Webhook URL!"});
  if(!isStaticIPAddress(req.body.ipaddress)) return res.send({"status": false, "message": "Please Enter Correct IP Address!"});
  const id = await createUniquePassword();
  await dbuser.push(req.session.username, {"id": id, "webhookurl": req.body.webhookurl, "ip": req.body.ipaddress})
  await db.set(id, {"username": req.session.username, "webhookurl": req.body.webhookurl, "ip": req.body.ipaddress})
  await res.send({"status": true})
})

app.post("/api/webhookdelete", async(req, res) => {
  const db = new Database("./database/webhook.json");
  if(!req.session.durum) return res.send({"status": false, "message": "Please Log In Again!"});
  if(!db.get(req.body.webhookid)) return res.send({"status": false, "message": "Webhook Not Find!"});
  
  const webhookDeleted = deleteWebhookData(req.session.username, req.body.webhookid);
  if (!webhookDeleted) {
    return res.send({ "status": false, "message": "Webhook ID Not Found!" });
  }
  
  await db.remove(req.body.webhookid)
  await res.send({"status": true})
})

app.post("/api/login", async(req, res) => {
  const db = new Database("./database/users.json")
  if(!db.get(req.body.username)) return res.send({"status": false, "message": "Your Username or Password is Incorrect!"});
  if(req.body.password != await db.get(req.body.username).password) return res.send({"status": false, "message": "Your Username or Password is Incorrect!"});
  req.session.regenerate(function (err) {
    if (err) next(err)

    req.session.durum = true;
    req.session.username = req.body.username;
    req.session.email = req.body.email;
    req.session.discordID = req.body.discordID;
    req.session.save(function (err) {
      if (err) return next(err)
      res.send({"status": true})
    })
  })
})

app.post("/api/register", async(req, res) => {
  const db = new Database("./database/users.json")
  const fRes = await fetch(`https://canary.discord.com/api/v10/users/${req.body.discordID}`, {
    headers: {
        "Content-Type": "application/json",
        Authorization: `Bot ${config.token}`,
    },
  })
  const json = await fRes.json()
  if(json.message === "Unknown User") return res.send({"status": false, "message": "There is no Discord Account for this Discord ID!"})
  // You must be on the Ang Bot's Service Server to Register! DISCORD.GG/ANGBOTS
  await db.set(req.body.username, { "email": req.body.mail, "password": req.body.password, "discordID": req.body.discordID})
  await res.send({"status": true});
})

app.listen(port, () => {
  console.log(`Example app listening on port http://${config.domain}:${port}`)
})

app.use((err, req, res, next) => {
  console.error("Error caught:", err.message);
  console.error(err.stack); // Hatanın detaylı çıktısı
  res.status(500).json({ error: "Internal Server Error" });
});

function generatePassword() {
  const charset =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  let password = "";
  for (let i = 0; i < 69; i++) {
      password += charset[crypto.randomInt(0, charset.length)];
  }
  return password;
}

async function createUniquePassword() {
  let password;
  const db = new Database("./database/webhook.json");
  do {
      password = generatePassword();
  } while (db.has(password)); // Şifreyi doğrudan kontrol et
  return password;
}

function isStaticIPAddress(input) {
  // IPv4 adres kontrolü
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$/;

  // IPv6 adres kontrolü
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9]))$/;

  // Kontrol
  return ipv4Regex.test(input) || ipv6Regex.test(input);
}

function isDiscordWebhook(url) {
  // Discord webhook URL'sini kontrol eden regex
  const discordWebhookRegex = /^https:\/\/discord\.com\/api\/webhooks\/\d+\/[\w-]+$/;

  // URL stringi regex ile doğrula
  return discordWebhookRegex.test(url);
}

function deleteWebhookData(username, webhookIdToDelete) {
  // userwebhook.json dosyasını okuma
  const userWebhookPath = path.join(__dirname, './database/userwebhook.json');
  const webhookData = JSON.parse(fs.readFileSync(userWebhookPath, 'utf8'));

  // Kullanıcının webhook'ları varsa
  if (webhookData[username]) {
    const updatedUserWebhooks = webhookData[username].filter(element => element.id !== webhookIdToDelete);

    // Eğer id'yi bulup silmişsek, veriyi güncelle
    if (webhookData[username].length !== updatedUserWebhooks.length) {
      webhookData[username] = updatedUserWebhooks;
      // Güncellenmiş veriyi dosyaya yazma
      fs.writeFileSync(userWebhookPath, JSON.stringify(webhookData, null, 2), 'utf8');
      return true;
    }
  }

  // Webhook ID'si bulunamadıysa
  return false;
}