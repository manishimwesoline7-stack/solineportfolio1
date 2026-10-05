<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

/* ================= 1. CONFIG — EDIT ME ================= */
const SITE_NAME  = "Soline 💜";
const ADMIN_USER = 'soline';
const ADMIN_PASS = 'soline2009';      // ← CHANGE THIS!
const BIRTHDAY   = '2009-10-03';

 $SKILLS = ['Python'=>92,'React'=>85,'Machine Learning'=>80,'HTML/CSS'=>90,'Cyber Security'=>75];

 $DB_HOST='localhost'; $DB_NAME='soline_db'; $DB_USER='root'; $DB_PASS='';
const UPLOAD_DIR = __DIR__ . '/uploads';
const MAX_IMG_MB = 5;
const MAX_VID_MB = 200;

/* ================= 2. DATABASE (AUTO-CREATED) ================= */
try {
    $pdo = new PDO("mysql:host=127.0.0.1;charset=utf8mb4", $DB_USER, $DB_PASS,
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]);
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `$DB_NAME` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $pdo->exec("USE `$DB_NAME`");

    $pdo->exec("CREATE TABLE IF NOT EXISTS users(
        id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL,
        role ENUM('user','admin') DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS posts(
        id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(200) NOT NULL,
        excerpt TEXT, content LONGTEXT, image VARCHAR(255) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS media(
        id INT AUTO_INCREMENT PRIMARY KEY, type ENUM('image','video') NOT NULL,
        title VARCHAR(200) NOT NULL, file_path VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS messages(
        id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL,
        sender ENUM('user','admin') NOT NULL, message TEXT NOT NULL,
        is_read TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS scores(
        id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL,
        game VARCHAR(20) NOT NULL, score INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)");
    /* upgrade old installs */
    try { $pdo->exec("ALTER TABLE messages ADD COLUMN is_read TINYINT(1) DEFAULT 0"); } catch (PDOException $ex) {}

    if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0775, true);

    $q=$pdo->prepare("SELECT id FROM users WHERE username=?");
    $q->execute([ADMIN_USER]);
    if (!$q->fetch())
        $pdo->prepare("INSERT INTO users(username,email,password,role) VALUES(?,?,?,'admin')")
            ->execute([ADMIN_USER,'soline@localhost',password_hash(ADMIN_PASS,PASSWORD_DEFAULT)]);
} catch (PDOException $ex){ die('DB error: '.$ex->getMessage()); }

/* ================= 3. HELPERS ================= */
function e($s){ return htmlspecialchars((string)($s??''),ENT_QUOTES,'UTF-8'); }
function isLogged(){ return !empty($_SESSION['uid']); }
function isAdmin(){ return isLogged() && ($_SESSION['role']??'')==='admin'; }
function needLogin(){ if(!isLogged()){ $_SESSION['flash']='🔒 Please login first 💜'; header('Location: ?page=login'); exit; } }
function needAdmin(){ if(!isAdmin()){ header('Location: ?page=login'); exit; } }
function flash($msg,$to){ $_SESSION['flash']=$msg; header('Location: ?page='.$to); exit; }
function myAge(){ return (new DateTime(BIRTHDAY))->diff(new DateTime())->y; }
function csrf(){ if(empty($_SESSION['tok'])) $_SESSION['tok']=bin2hex(random_bytes(16)); return $_SESSION['tok']; }
function csrfField(){ return '<input type="hidden" name="csrf" value="'.csrf().'">'; }
function csrfOK($t){ return hash_equals($_SESSION['tok']??'', $t??''); }

function upload($field, array $mimes, int $maxMB, string $sub, string &$err): string {
    if(!isset($_FILES[$field])||$_FILES[$field]['error']!==UPLOAD_ERR_OK){ $err='Upload failed (file missing or too big).'; return ''; }
    $f=$_FILES[$field];
    if($f['size']>$maxMB*1048576){ $err='Too big — max '.$maxMB.' MB.'; return ''; }
    $mime=(new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']);
    if(!in_array($mime,$mimes,true)){ $err='That file type is not allowed.'; return ''; }
    $ext=strtolower(pathinfo($f['name'],PATHINFO_EXTENSION));
    $name=date('Ymd_His').'_'.bin2hex(random_bytes(5)).'.'.$ext;
    $dir=UPLOAD_DIR.'/'.$sub; if(!is_dir($dir)) mkdir($dir,0775,true);
    if(!move_uploaded_file($f['tmp_name'],$dir.'/'.$name)){ $err='Could not save file.'; return ''; }
    return $name;
}

/* ================= 4. POST ACTIONS (all CSRF-protected) ================= */
 $page = $_GET['page'] ?? 'home';

if ($_SERVER['REQUEST_METHOD']==='POST' && !csrfOK($_POST['csrf']??''))
    die('Invalid security token — go back and retry.');

if ($_SERVER['REQUEST_METHOD']==='POST') switch ($_POST['action'] ?? '') {

case 'register':
    $u=trim($_POST['username']??''); $m=trim($_POST['email']??'');
    $p=$_POST['password']??'';       $c=$_POST['confirm']??'';
    if(!$u||!$m||!$p)                         flash('All fields are required.','register');
    if(!filter_var($m,FILTER_VALIDATE_EMAIL)) flash('Please enter a valid email.','register');
    if(strlen($p)<6)                          flash('Password must be 6+ characters.','register');
    if($p!==$c)                               flash('Passwords do not match.','register');
    $q=$pdo->prepare("SELECT id FROM users WHERE username=? OR email=?"); $q->execute([$u,$m]);
    if($q->fetch())                           flash('Username or email already taken.','register');
    $pdo->prepare("INSERT INTO users(username,email,password,role) VALUES(?,?,?,'user')")
        ->execute([$u,$m,password_hash($p,PASSWORD_DEFAULT)]);
    flash('Account created 🎉 Now login!','login');

case 'login':
    $l=trim($_POST['login']??''); $p=$_POST['password']??'';
    $q=$pdo->prepare("SELECT * FROM users WHERE username=? OR email=?"); $q->execute([$l,$l]);
    $usr=$q->fetch();
    if($usr && password_verify($p,$usr['password'])){
        session_regenerate_id(true);
        $_SESSION['uid']=$usr['id']; $_SESSION['uname']=$usr['username']; $_SESSION['role']=$usr['role'];
        flash('Welcome, '.$usr['username'].'! '.($usr['role']==='admin'?'👑':'💜'),'home');
    }
    flash('Wrong username or password.','login');

case 'new_post':                       /* ADMIN ONLY */
    needAdmin();
    $t=trim($_POST['title']??'');$x=trim($_POST['excerpt']??'');$c=trim($_POST['content']??'');
    if(!$t||!$c) flash('Title and content are required.','admin');
    $img='';$err='';
    if(!empty($_FILES['image']['name']))
        $img=upload('image',['image/jpeg','image/png','image/gif','image/webp'],MAX_IMG_MB,'images',$err);
    if($err) flash($err,'admin');
    $pdo->prepare("INSERT INTO posts(title,excerpt,content,image)VALUES(?,?,?,?)")->execute([$t,$x,$c,$img]);
    flash('Blog post published! 🎉','admin');

case 'upload_image':                   /* ADMIN ONLY */
    needAdmin();
    $err='';$f=upload('file',['image/jpeg','image/png','image/gif','image/webp'],MAX_IMG_MB,'images',$err);
    if($err) flash($err,'admin');
    $pdo->prepare("INSERT INTO media(type,title,file_path)VALUES('image',?,?)")
        ->execute([trim($_POST['title']??'') ?: 'Untitled',$f]);
    flash('Image uploaded! 📸','admin');

case 'upload_video':                   /* ADMIN ONLY */
    needAdmin();
    $err='';$f=upload('file',['video/mp4','video/webm','video/ogg'],MAX_VID_MB,'videos',$err);
    if($err) flash($err,'admin');
    $pdo->prepare("INSERT INTO media(type,title,file_path)VALUES('video',?,?)")
        ->execute([trim($_POST['title']??'') ?: 'Untitled',$f]);
    flash('Video uploaded! 🎬','admin');

case 'delete_post':
    needAdmin();
    $pdo->prepare("DELETE FROM posts WHERE id=?")->execute([(int)($_POST['id']??0)]);
    flash('Post deleted.','admin');

case 'delete_media':
    needAdmin();
    $q=$pdo->prepare("SELECT * FROM media WHERE id=?");$q->execute([(int)($_POST['id']??0)]);
    if($m=$q->fetch()){
        @unlink(UPLOAD_DIR.'/'.$m['type'].'s/'.basename($m['file_path']));
        $pdo->prepare("DELETE FROM media WHERE id=?")->execute([$m['id']]);
    }
    flash('Media deleted.','admin');

case 'reset_scores':                   /* ADMIN ONLY */
    needAdmin();
    $pdo->exec("DELETE FROM scores");
    flash('Leaderboard reset 🧹','game');
}

/* ================= 5. AJAX APIs ================= */

/* ---- save game score (users only) ---- */
if($page==='score_api' && $_SERVER['REQUEST_METHOD']==='POST'){
    header('Content-Type: application/json');
    if(!isLogged() || isAdmin()){ echo json_encode(['error'=>1]); exit; }
    $game=($_POST['game']??'')==='quiz'?'quiz':'snake';
    $score=max(0,min(500,(int)($_POST['score']??0)));
    $pdo->prepare("INSERT INTO scores(user_id,game,score)VALUES(?,?,?)")->execute([$_SESSION['uid'],$game,$score]);
    echo json_encode(['ok'=>1]); exit;
}

/* ---- leaderboard ---- */
if($page==='board_api'){
    header('Content-Type: application/json');
    $game=($_GET['game']??'')==='quiz'?'quiz':'snake';
    $q=$pdo->prepare("SELECT u.username, MAX(s.score) sc FROM scores s JOIN users u ON u.id=s.user_id
                      WHERE s.game=? GROUP BY s.user_id ORDER BY sc DESC LIMIT 10");
    $q->execute([$game]);
    echo json_encode($q->fetchAll()); exit;
}

/* ---- unread message count (navbar badge) ---- */
if($page==='unread_api'){
    header('Content-Type: application/json');
    if(!isLogged()){ echo json_encode(['n'=>0]); exit; }
    if(isAdmin()){
        $n=(int)$pdo->query("SELECT COUNT(*) c FROM messages WHERE sender='user' AND is_read=0")->fetch()['c'];
    } else {
        $q=$pdo->prepare("SELECT COUNT(*) c FROM messages WHERE user_id=? AND sender='admin' AND is_read=0");
        $q->execute([$_SESSION['uid']]); $n=(int)$q->fetch()['c'];
    }
    echo json_encode(['n'=>$n]); exit;
}

/* ---- chat: send + receive ---- */
if($page==='chat_api'){
    header('Content-Type: application/json');
    if(!isLogged()){ echo json_encode(['error'=>'login']); exit; }

    if($_SERVER['REQUEST_METHOD']==='POST'){
        $msg=mb_substr(trim($_POST['message']??''),0,1000);
        if($msg!==''){
            if(isAdmin()){
                $to=(int)($_POST['to']??0);
                if($to) $pdo->prepare("INSERT INTO messages(user_id,sender,message)VALUES(?,'admin',?)")->execute([$to,$msg]);
            } else {
                $pdo->prepare("INSERT INTO messages(user_id,sender,message)VALUES(?,'user',?)")->execute([$_SESSION['uid'],$msg]);
            }
        }
        echo json_encode(['ok'=>1]); exit;
    }

    $with = isAdmin() ? (int)($_GET['with']??0) : (int)$_SESSION['uid'];
    if($with<=0){ echo json_encode([]); exit; }
    $q=$pdo->prepare("SELECT sender,message,DATE_FORMAT(created_at,'%b %d · %H:%i') t
                      FROM messages WHERE user_id=? ORDER BY id ASC LIMIT 300");
    $q->execute([$with]);
    $rows=$q->fetchAll();
    if(isAdmin())
        $pdo->prepare("UPDATE messages SET is_read=1 WHERE user_id=? AND sender='user' AND is_read=0")->execute([$with]);
    else
        $pdo->prepare("UPDATE messages SET is_read=1 WHERE user_id=? AND sender='admin' AND is_read=0")->execute([$with]);
    echo json_encode($rows); exit;
}

if($page==='logout'){ session_unset(); session_destroy(); header('Location: ?page=home'); exit; }

/* ================= 6. PAGES ================= */
function page_home(): string {
    global $pdo,$SKILLS; ob_start();
    $posts =$pdo->query("SELECT * FROM posts ORDER BY created_at DESC LIMIT 3")->fetchAll();
    $images=$pdo->query("SELECT * FROM media WHERE type='image' ORDER BY created_at DESC LIMIT 6")->fetchAll();
    $nUsers=(int)$pdo->query("SELECT COUNT(*) c FROM users WHERE role='user'")->fetch()['c'];
?>
<section class="hero reveal">
  <div id="particles"></div>
  <div class="avatar">👩‍💻</div>
  <h1>Hi, I'm <span class="grad">Manishimwe Soline</span></h1>
  <p class="type-line"><span id="typed"></span><span class="cursor">|</span></p>
  <p class="sub">Student at L5SOD · Lycée Saint Alexandre Sauli de Muhura · I love coding 💻 · Future Cyber Security Expert 🛡️</p>
  <a class="btn" href="?page=about">✨ About me</a>
  <a class="btn alt" href="?page=game">🎮 Play games</a>
  <a class="btn alt" href="?page=chat">💬 Chat with me</a>
  <p class="muted small" style="margin-top:14px">👥 <?= $nUsers ?> members already joined!</p>
</section>

<section class="stats reveal">
  <div class="stat"><b>🎂 <?= myAge() ?></b><span>years old</span></div>
  <div class="stat"><b>👨‍👩‍👧‍👦 5</b><span>family members</span></div>
  <div class="stat"><b>🐍⚛️🤖</b><span>Python · React · ML</span></div>
  <div class="stat"><b>🛡️</b><span>Cyber Security dream</span></div>
</section>

<section class="reveal"><h2>⚙️ My Skills</h2>
  <div class="split">
    <div class="glass chartbox"><canvas id="chart"></canvas></div>
    <div class="glass pad">
      <?php foreach(['Python'=>92,'React'=>85,'Machine Learning'=>80] as $n=>$v): ?>
      <div class="bar-row"><b><?= $n ?> · <?= $v ?>%</b>
        <div class="bar"><i style="--w:<?= $v ?>%"></i></div>
      </div>
      <?php endforeach; ?>
      <p class="muted small">My big goal is Cyber Security 🛡️</p>
    </div>
  </div>
</section>

<section class="reveal"><h2>📝 Latest Blog</h2>
  <div class="grid">
    <?php if(!$posts) echo '<p class="muted">No posts yet — check the Admin panel!</p>';
    foreach($posts as $p): ?>
    <article class="glass card">
      <?php if($p['image']): ?><img src="uploads/images/<?= e($p['image']) ?>" alt=""><?php endif; ?>
      <h3><?= e($p['title']) ?></h3>
      <p><?= e(mb_substr($p['excerpt'] ?: strip_tags($p['content']),0,110)) ?>…</p>
      <a class="btn small" href="?page=post&id=<?= $p['id'] ?>">Read more 🔒</a>
    </article>
    <?php endforeach; ?>
  </div>
</section>

<section class="reveal"><h2>🖼️ Gallery</h2>
  <div class="grid">
    <?php if(!$images): foreach([['💻','Coding'],['🛡️','Cyber Security'],['🏫','My School L5SOD'],['🎵','Emotional Songs'],['🎬','HS Movies'],['👯‍♀️','Bestie Bonette']] as $g): ?>
      <figure class="glass card empty-tile"><div class="big"><?= $g[0] ?></div><figcaption><?= $g[1] ?></figcaption></figure>
    <?php endforeach; else: foreach($images as $im): ?>
      <figure class="glass card"><img src="uploads/images/<?= e($im['file_path']) ?>" alt=""><figcaption class="muted"><?= e($im['title']) ?></figcaption></figure>
    <?php endforeach; endif; ?>
  </div>
</section>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
new Chart(document.getElementById('chart'),{type:'radar',
 data:{labels:<?= json_encode(array_keys($SKILLS)) ?>,
  datasets:[{label:'My level (%)',data:<?= json_encode(array_values($SKILLS)) ?>,
  backgroundColor:'rgba(255,77,148,.25)',borderColor:'#ff4d94',pointBackgroundColor:'#00e5ff'}]},
 options:{scales:{r:{beginAtZero:true,max:100,grid:{color:'rgba(255,255,255,.15)'},
  angleLines:{color:'rgba(255,255,255,.15)'},pointLabels:{color:'#fff',font:{size:13}},
  ticks:{color:'#c9b8e8',backdropColor:'transparent',stepSize:25}}},
  plugins:{legend:{labels:{color:'#fff'}}}}});
</script>
<?php return ob_get_clean(); }

function page_about(): string { ob_start(); ?>
<h1 class="reveal">💜 About Me</h1>
<div class="split reveal">
  <div class="glass pad about-photo"><div class="avatar big">👩‍💻</div>
    <p class="muted small">(Admin can upload a real photo!)</p></div>
  <div class="glass pad">
    <p>Hello! I'm <b>Manishimwe Soline</b>, born on <b>03-10-2009</b> (🎂 <?= myAge() ?> years old).
    I study at <b>L5SOD — Lycée Saint Alexandre Sauli de Muhura</b>.</p>
    <p>I simply <b>love coding 💻</b> — Python and React make me happy.
    My biggest dream is to <b>study Cyber Security 🛡️</b>.</p>
    <p>In my free time I enjoy <b>high school movies 🎬</b> and <b>emotional songs 🎵</b>.
    My best friend <b>Bonette 👯‍♀️</b> — same school, same class!</p>
  </div>
</div>

<h2 class="reveal">👨‍👩‍👧‍👦 My Family — 5 Members</h2>
<div class="grid reveal">
  <?php foreach([
    ['👨','Donatien','My Dad','The head of our family 💪'],
    ['👩','Christine','My Mom','Full of love and care 💕'],
    ['🧑','Samuel','Big Brother','First born — my role model ⭐'],
    ['💜','Soline','Me!','2nd born · born 03-10-2009'],
    ['🧒','Servant','Last Born','The youngest 🌟'],
  ] as $f): ?>
  <div class="glass card center">
    <div class="fam-emoji"><?= $f[0] ?></div>
    <h3><?= $f[1] ?></h3><p class="tag"><?= $f[2] ?></p><p class="muted small"><?= $f[3] ?></p>
  </div>
  <?php endforeach; ?>
</div>

<h2 class="reveal">🚀 My Journey</h2>
<div class="timeline reveal">
  <div class="tl"><span>✅</span><div><b>Now</b><p>Studying at L5SOD & learning to code 💻</p></div></div>
  <div class="tl"><span>🎓</span><div><b>Next</b><p>Finish high school with great results</p></div></div>
  <div class="tl"><span>🏛️</span><div><b>Future</b><p>University — study Cyber Security</p></div></div>
  <div class="tl"><span>🛡️</span><div><b>Dream</b><p>Become a Cyber Security Expert!</p></div></div>
</div>
<?php return ob_get_clean(); }

function page_blog(): string {
    global $pdo; ob_start();
    $posts=$pdo->query("SELECT * FROM posts ORDER BY created_at DESC")->fetchAll(); ?>
<h1 class="reveal">📝 My Blog</h1>
<div class="grid reveal">
  <?php if(!$posts) echo '<p class="muted">No posts yet.</p>';
  foreach($posts as $p): ?>
  <article class="glass card">
    <?php if($p['image']): ?><img src="uploads/images/<?= e($p['image']) ?>" alt=""><?php endif; ?>
    <h3><?= e($p['title']) ?></h3>
    <p class="muted small"><?= date('M j, Y',strtotime($p['created_at'])) ?></p>
    <p><?= e(mb_substr($p['excerpt'] ?: strip_tags($p['content']),0,120)) ?>…</p>
    <a class="btn small" href="?page=post&id=<?= $p['id'] ?>">Read more 🔒</a>
  </article>
  <?php endforeach; ?>
</div>
<?php return ob_get_clean(); }

function page_post(): string {
    global $pdo; ob_start();
    $q=$pdo->prepare("SELECT * FROM posts WHERE id=?"); $q->execute([(int)($_GET['id']??0)]);
    $p=$q->fetch();
    if(!$p){ echo '<h1>404</h1><p><a href="?page=blog">← Back to blog</a></p>'; return ob_get_clean(); } ?>
<?php if($p['image']): ?><img class="cover" src="uploads/images/<?= e($p['image']) ?>" alt=""><?php endif; ?>
<h1><?= e($p['title']) ?></h1>
<p class="muted small"><?= date('F j, Y',strtotime($p['created_at'])) ?></p>
<?php if(!isLogged()): ?>
  <div class="glass pad"><p><?= e(mb_substr($p['excerpt'] ?: strip_tags($p['content']),0,200)) ?>…</p></div>
  <div class="lock reveal">🔒 <b>The rest of this article is for members!</b>
    <p><a class="btn" href="?page=login">Login</a> <a class="btn alt" href="?page=register">Register free</a></p></div>
<?php else: ?>
  <div class="glass pad article"><?= nl2br(e($p['content'])) ?></div>
<?php endif; ?>
<p style="margin-top:16px"><a href="?page=blog">← Back to all posts</a></p>
<?php return ob_get_clean(); }

function page_gallery(): string {
    global $pdo; ob_start();
    $imgs=$pdo->query("SELECT * FROM media WHERE type='image' ORDER BY created_at DESC")->fetchAll(); ?>
<h1 class="reveal">🖼️ Gallery</h1>
<div class="grid reveal">
  <?php if(!$imgs) echo '<p class="muted">No photos yet — Admin will upload some soon! 📸</p>';
  foreach($imgs as $im): ?>
  <figure class="glass card"><img src="uploads/images/<?= e($im['file_path']) ?>" alt="">
    <figcaption class="muted"><?= e($im['title']) ?></figcaption></figure>
  <?php endforeach; ?>
</div>
<?php return ob_get_clean(); }

function page_videos(): string {
    global $pdo; needLogin(); ob_start();
    $vids=$pdo->query("SELECT * FROM media WHERE type='video' ORDER BY created_at DESC")->fetchAll(); ?>
<h1 class="reveal">🎬 Videos</h1>
<?php if(!$vids) echo '<p class="muted">No videos yet — coming soon! 🎥</p>';
foreach($vids as $v): ?>
  <div class="glass pad reveal" style="margin-bottom:22px">
    <h3><?= e($v['title']) ?></h3>
    <video controls preload="metadata" src="uploads/videos/<?= e($v['file_path']) ?>"></video>
  </div>
<?php endforeach;
    return ob_get_clean(); }

/* ---------------- GAMES (USERS ONLY) ---------------- */
function page_game(): string {
    global $pdo; ob_start();
    if (!isLogged()): ?>
      <div class="lock reveal">🎮 <b>Games are for registered users only!</b>
        <p style="margin-top:8px">Register free, then play Snake 🐍 and the Cyber Quiz 🛡️ — and appear on the leaderboard 🏆</p>
        <p><a class="btn" href="?page=login">Login</a> <a class="btn alt" href="?page=register">Register</a></p>
      </div>
      <?php return ob_get_clean();
    endif;

    $boardQ=$pdo->prepare("SELECT u.username, MAX(s.score) sc FROM scores s JOIN users u ON u.id=s.user_id
                           WHERE s.game=? GROUP BY s.user_id ORDER BY sc DESC LIMIT 10");
    $boardQ->execute(['snake']); $snakeBoard=$boardQ->fetchAll();
    $boardQ->execute(['quiz']);  $quizBoard=$boardQ->fetchAll();
?>
<h1 class="reveal">🎮 Game Zone</h1>
<?php if(isAdmin()): ?>
  <div class="glass pad reveal">
    <p>👑 <b>You are the Admin</b> — games are played by your <b>users</b> (visitors who register).
    Share the site so they join and play! Their scores appear below.</p>
    <form method="post" onsubmit="return confirm('Reset ALL scores?')" style="margin-top:10px">
      <?= csrfField() ?><input type="hidden" name="action" value="reset_scores">
      <button class="btn danger">🧹 Reset leaderboard</button>
    </form>
  </div>
<?php else: ?>
<p class="muted reveal">Play, get a high score, and appear on the leaderboard! 🏆</p>
<div class="split reveal">
  <div class="glass pad center">
    <h2>🐍 Snake</h2>
    <p>Score: <b id="snakeScore">0</b> — Arrow keys / WASD</p>
    <canvas id="snake" width="400" height="400"></canvas>
    <div class="pad-controls">
      <button class="pad-btn" onclick="setDir(0,-1)">▲</button>
      <div><button class="pad-btn" onclick="setDir(-1,0)">◀</button>
           <button class="pad-btn" onclick="setDir(1,0)">▶</button></div>
      <button class="pad-btn" onclick="setDir(0,1)">▼</button>
    </div>
    <button class="btn" onclick="startSnake()">▶ Start / Restart</button>
  </div>
  <div class="glass pad center">
    <h2>🛡️ Cyber Security Quiz</h2>
    <div id="quizBox"><p class="muted">Test your cyber knowledge! 10 questions.</p>
      <button class="btn" onclick="startQuiz()">▶ Start Quiz</button></div>
  </div>
</div>
<?php endif; ?>

<div class="split reveal">
  <div class="glass pad"><h3>🏆 Snake Leaderboard</h3><ol id="boardSnake" class="board">
    <?php foreach($snakeBoard as $i=>$r): ?><li><?= ['🥇','🥈','🥉'][$i] ?? '▫️' ?> <?= e($r['username']) ?> — <b><?= (int)$r['sc'] ?></b></li><?php endforeach; ?>
    <?php if(!$snakeBoard) echo '<li class="muted">No scores yet</li>'; ?>
  </ol></div>
  <div class="glass pad"><h3>🏆 Quiz Leaderboard</h3><ol id="boardQuiz" class="board">
    <?php foreach($quizBoard as $i=>$r): ?><li><?= ['🥇','🥈','🥉'][$i] ?? '▫️' ?> <?= e($r['username']) ?> — <b><?= (int)$r['sc'] ?></b></li><?php endforeach; ?>
    <?php if(!$quizBoard) echo '<li class="muted">No scores yet</li>'; ?>
  </ol></div>
</div>

<?php if(!isAdmin()): ?>
<script>
const CSRF='<?= csrf() ?>';
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
function medal(i){return ['🥇','🥈','🥉'][i]||'▫️';}
function saveScore(game,score){
  fetch('?page=score_api',{method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'game='+game+'&score='+score+'&csrf='+CSRF
  }).then(r=>r.json()).then(d=>{ if(d.ok)refreshBoard(game); });
}
function refreshBoard(g){
  fetch('?page=board_api&game='+g).then(r=>r.json()).then(rows=>{
    const el=document.getElementById(g==='snake'?'boardSnake':'boardQuiz');
    if(!el)return;
    el.innerHTML=rows.map((r,i)=>'<li>'+medal(i)+' '+esc(r.username)+' — <b>'+r.sc+'</b></li>').join('')
      ||'<li class="muted">No scores yet</li>';
  });
}

/* ---------- SNAKE ---------- */
const cvs=document.getElementById('snake'),ctx=cvs?cvs.getContext('2d'):null;
let snake,dir,nDir,food,score=0,alive=false,timer=null,SPEED=130;const N=20;
function startSnake(){
  snake=[{x:8,y:10},{x:7,y:10},{x:6,y:10}];dir={x:1,y:0};nDir=dir;
  score=0;alive=true;SPEED=130;document.getElementById('snakeScore').textContent='0';
  placeFood();draw();if(timer)clearInterval(timer);timer=setInterval(tick,SPEED);
}
function placeFood(){do{food={x:Math.floor(Math.random()*N),y:Math.floor(Math.random()*N)};}
  while(snake.some(s=>s.x===food.x&&s.y===food.y));}
function setDir(x,y){ if(alive && !(x===-dir.x&&y===-dir.y)) nDir={x,y}; }
document.addEventListener('keydown',ev=>{
  const k=ev.key.toLowerCase();
  if(k==='arrowup'||k==='w'){setDir(0,-1);ev.preventDefault();}
  if(k==='arrowdown'||k==='s'){setDir(0,1);ev.preventDefault();}
  if(k==='arrowleft'||k==='a'){setDir(-1,0);ev.preventDefault();}
  if(k==='arrowright'||k==='d'){setDir(1,0);ev.preventDefault();}
});
function tick(){
  if(!alive)return;dir=nDir;
  const h={x:snake[0].x+dir.x,y:snake[0].y+dir.y};
  if(h.x<0||h.x>=N||h.y<0||h.y>=N||snake.some(s=>s.x===h.x&&s.y===h.y)){gameOver();return;}
  snake.unshift(h);
  if(h.x===food.x&&h.y===food.y){
    score+=10;document.getElementById('snakeScore').textContent=score;placeFood();
    if(SPEED>60){SPEED-=5;clearInterval(timer);timer=setInterval(tick,SPEED);}
  } else snake.pop();
  draw();
}
function draw(){
  ctx.fillStyle='#120b24';ctx.fillRect(0,0,400,400);
  ctx.font='16px serif';ctx.fillText('🌸',food.x*20+2,food.y*20+17);
  snake.forEach((s,i)=>{ctx.fillStyle=i===0?'#00e5ff':'#b967ff';
    ctx.fillRect(s.x*20+1,s.y*20+1,18,18);});
}
function gameOver(){
  alive=false;clearInterval(timer);
  ctx.fillStyle='rgba(10,5,25,.88)';ctx.fillRect(0,0,400,400);
  ctx.fillStyle='#fff';ctx.font='22px Segoe UI';ctx.textAlign='center';
  ctx.fillText('Game Over! Score: '+score,200,190);
  ctx.font='14px Segoe UI';ctx.fillText('Press Start to try again 💜',200,220);
  if(score>0)saveScore('snake',score);
}

/* ---------- QUIZ ---------- */
const QUIZ=[
 {q:'What does "phishing" try to steal?',o:['Your passwords & personal info 🎣','Your WiFi speed','Your screen size','Your battery'],a:0},
 {q:'A strong password is…',o:['Long with letters, numbers & symbols 🔐','Your own name','123456','The same everywhere'],a:0},
 {q:'What is 2FA?',o:['Two-factor authentication 📲','Two funny animals','A phone brand','A game level'],a:0},
 {q:'HTTPS means the site is…',o:['Encrypted & safer 🔒','Faster','Free','Brand new'],a:0},
 {q:'A computer virus is a type of…',o:['Malware 🦠','Hardware','Browser','Cable'],a:0},
 {q:'A strange link in an email? You should…',o:['Not click it 🚫','Click it fast','Share with friends','Reply with your password'],a:0},
 {q:'A firewall…',o:['Blocks unauthorized access 🧱','Cools the PC','Draws art','Prints files'],a:0},
 {q:'SQL injection attacks…',o:['Databases 🗄️','Monitors','Keyboards','Speakers'],a:0},
 {q:'A "white hat" hacker is…',o:['A good security hacker 🤍','A chef','A painter','A ghost'],a:0},
 {q:'Encryption turns data into…',o:['Secret unreadable code 🔑','Pictures','Music','Emojis'],a:0},
];
let qi=0,qscore=0;
function startQuiz(){qi=0;qscore=0;showQ();}
function showQ(){
  const b=document.getElementById('quizBox');
  if(qi>=QUIZ.length){finishQuiz();return;}
  const Q=QUIZ[qi],order=[...Q.o.keys()].sort(()=>Math.random()-.5);
  b.innerHTML='<p class="muted">Question '+(qi+1)+' / '+QUIZ.length+' · Score: '+qscore+'</p>'
   +'<h3>'+esc(Q.q)+'</h3><div class="qopts">'
   +order.map(i=>'<button class="qbtn" onclick="pick('+i+')">'+esc(Q.o[i])+'</button>').join('')+'</div>';
}
function pick(i){ if(i===QUIZ[qi].a)qscore+=10; qi++; showQ(); }
function finishQuiz(){
  const msg=qscore>=80?'🌟 Amazing! You are a cyber hero!':qscore>=50?'👍 Good job — keep learning!':'💪 Keep practicing — you will get there!';
  document.getElementById('quizBox').innerHTML=
   '<h3>Result: '+qscore+' / 100</h3><p>'+msg+'</p><button class="btn" onclick="startQuiz()">↻ Play again</button>';
  saveScore('quiz',qscore);
}
</script>
<?php endif;
    return ob_get_clean(); }

/* ---------------- CHAT (admin ↔ users) ---------------- */
function page_chat(): string {
    global $pdo; needLogin(); ob_start();
    $with=0; $chatUsers=[];
    if(isAdmin()){
        $chatUsers=$pdo->query("SELECT u.id,u.username,
            (SELECT COUNT(*) FROM messages m WHERE m.user_id=u.id AND m.sender='user' AND m.is_read=0) unread
            FROM users u WHERE u.role='user' ORDER BY unread DESC, u.username")->fetchAll();
        $with=(int)($_GET['with'] ?? ($chatUsers[0]['id'] ?? 0));
        if(!$with){ echo '<h1>💬 Live Chat</h1><p class="muted">No users yet — when they register you can chat with them here 💜</p>'; return ob_get_clean(); }
    }
?>
<h1 class="reveal">💬 Live Chat <?= isAdmin()?'<span class="tag">— Admin mode 👑</span>':'' ?></h1>
<div class="chat reveal">
  <?php if(isAdmin()): ?>
  <div class="glass users"><b>👥 Users</b>
    <?php foreach($chatUsers as $usr): ?>
      <a class="<?= $usr['id']==$with?'on':'' ?>" href="?page=chat&with=<?= $usr['id'] ?>">
        <?= e($usr['username']) ?> <?= $usr['unread']>0?'<span class="ubadge">'.$usr['unread'].'</span>':'' ?>
      </a>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>
  <div class="glass chatbox">
    <div id="msgs"><p class="muted">Loading…</p></div>
    <form id="cform" class="cinput">
      <input id="cmsg" autocomplete="off" maxlength="1000" placeholder="Type a message and press Enter…" required>
      <button class="btn" id="sendBtn">Send ➤</button>
    </form>
  </div>
</div>
<script>
const API='?page=chat_api<?= isAdmin()?'&with='.$with:'' ?>';
const WITH=<?= (int)$with ?>;
const ME='<?= isAdmin()?'admin':'user' ?>';
const CSRF='<?= csrf() ?>';
const box=document.getElementById('msgs');
let last='',sending=false;
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
async function load(){
  try{
    const r=await fetch(API);const d=await r.json();
    if(d.error){location.href='?page=login';return;}
    const html=d.map(m=>'<div class="msg '+(m.sender===ME?'me':'them')+'">'
      +esc(m.message)+'<span class="t">'+esc(m.t)+'</span></div>').join('');
    if(html!==last){
      const stick=box.scrollHeight-box.scrollTop-box.clientHeight<90;
      box.innerHTML=html||'<p class="muted">No messages yet — say hi! 👋</p>';
      last=html; if(stick)box.scrollTop=box.scrollHeight;
      if(typeof updateBadge==='function')updateBadge();
    }
  }catch(e){}
}
document.getElementById('cform').onsubmit=async ev=>{
  ev.preventDefault();
  if(sending)return;
  const inp=document.getElementById('cmsg'),msg=inp.value.trim();if(!msg)return;
  sending=true;document.getElementById('sendBtn').disabled=true;
  const fd=new FormData();
  fd.append('message',msg);fd.append('csrf',CSRF);
  if(ME==='admin')fd.append('to',WITH);
  try{ await fetch(API,{method:'POST',body:fd}); inp.value=''; await load(); }
  finally{ sending=false;document.getElementById('sendBtn').disabled=false;inp.focus(); }
};
load(); setInterval(load,3000);
</script>
<?php return ob_get_clean(); }

function page_login(): string { ob_start(); ?>
<div class="glass pad formcard reveal">
  <h2>🔐 Login</h2>
  <form method="post"><?= csrfField() ?><input type="hidden" name="action" value="login">
    <label>Username or email</label><input name="login" required>
    <label>Password</label><input type="password" name="password" required>
    <button class="btn">Login 💜</button>
  </form>
  <p class="muted" style="margin-top:12px">New here? <a href="?page=register">Create a free account</a></p>
</div>
<?php return ob_get_clean(); }

function page_register(): string { ob_start(); ?>
<div class="glass pad formcard reveal">
  <h2>📝 Create Account <span class="tag">(role: user 👤)</span></h2>
  <form method="post"><?= csrfField() ?><input type="hidden" name="action" value="register">
    <label>Username</label><input name="username" required>
    <label>Email</label><input type="email" name="email" required>
    <label>Password (min 6)</label><input type="password" name="password" required>
    <label>Confirm password</label><input type="password" name="confirm" required>
    <button class="btn">Register 🎉</button>
  </form>
  <p class="muted" style="margin-top:12px">Already registered? <a href="?page=login">Login</a></p>
</div>
<?php return ob_get_clean(); }

/* ---------------- ADMIN PANEL (ADMIN ONLY) ---------------- */
function page_admin(): string {
    global $pdo; needAdmin(); ob_start();
    $posts=$pdo->query("SELECT * FROM posts ORDER BY created_at DESC")->fetchAll();
    $media=$pdo->query("SELECT * FROM media ORDER BY created_at DESC")->fetchAll();
    $nUsers=(int)$pdo->query("SELECT COUNT(*) c FROM users WHERE role='user'")->fetch()['c'];
    $unread=(int)$pdo->query("SELECT COUNT(*) c FROM messages WHERE sender='user' AND is_read=0")->fetch()['c'];
?>
<h1 class="reveal">⚙️ Admin Panel <span class="tag">👑</span></h1>
<p class="muted reveal">👥 <?= $nUsers ?> users · 📝 <?= count($posts) ?> posts · 🖼️🎬 <?= count($media) ?> media ·
   💬 <?= $unread ?> unread message<?= $unread==1?'':'s' ?></p>

<div class="split reveal">
  <div class="glass pad">
    <h3>📝 New blog post</h3>
    <form method="post" enctype="multipart/form-data"><?= csrfField() ?>
      <input type="hidden" name="action" value="new_post">
      <label>Title</label><input name="title" required>
      <label>Short excerpt (guests see this)</label><input name="excerpt">
      <label>Full content (members read this)</label><textarea name="content" required></textarea>
      <label>Cover image (optional)</label><input type="file" name="image" accept="image/*">
      <button class="btn">Publish ✔</button>
    </form>
  </div>
  <div class="glass pad">
    <h3>🖼️ Upload image</h3>
    <form method="post" enctype="multipart/form-data"><?= csrfField() ?>
      <input type="hidden" name="action" value="upload_image">
      <label>Title</label><input name="title" placeholder="e.g. Me and Bonette">
      <label>Image (JPG/PNG/GIF/WebP, max <?= MAX_IMG_MB ?>MB)</label>
      <input type="file" name="file" accept="image/*" required>
      <button class="btn">Upload ✔</button>
    </form>
    <h3 style="margin-top:20px">🎬 Upload video</h3>
    <form method="post" enctype="multipart/form-data"><?= csrfField() ?>
      <input type="hidden" name="action" value="upload_video">
      <label>Title</label><input name="title" placeholder="e.g. My school day">
      <label>Video (MP4/WebM, max <?= MAX_VID_MB ?>MB)</label>
      <input type="file" name="file" accept="video/*" required>
      <button class="btn">Upload ✔</button>
    </form>
  </div>
</div>

<h2 class="reveal">📝 Posts</h2>
<table class="glass reveal"><tr><th>Title</th><th>Date</th><th></th></tr>
<?php foreach($posts as $p): ?>
<tr><td><?= e($p['title']) ?></td><td class="muted"><?= date('M j, Y',strtotime($p['created_at'])) ?></td>
<td><form method="post" onsubmit="return confirm('Delete this post?')"><?= csrfField() ?>
  <input type="hidden" name="action" value="delete_post"><input type="hidden" name="id" value="<?= $p['id'] ?>">
  <button class="btn danger">Delete</button></form></td></tr>
<?php endforeach; if(!$posts) echo '<tr><td colspan="3" class="muted">No posts yet</td></tr>'; ?>
</table>

<h2 class="reveal">🎞️ Media</h2>
<table class="glass reveal"><tr><th>Title</th><th>Type</th><th></th></tr>
<?php foreach($media as $m): ?>
<tr><td><?= e($m['title']) ?></td><td><?= $m['type']==='video'?'🎬':'🖼️' ?></td>
<td><form method="post" onsubmit="return confirm('Delete this?')"><?= csrfField() ?>
  <input type="hidden" name="action" value="delete_media"><input type="hidden" name="id" value="<?= $m['id'] ?>">
  <button class="btn danger">Delete</button></form></td></tr>
<?php endforeach; if(!$media) echo '<tr><td colspan="3" class="muted">No media yet</td></tr>'; ?>
</table>
<p class="reveal"><a class="btn" href="?page=chat">💬 Reply to chat messages <?= $unread?'('.$unread.' unread 🔴)':'' ?></a></p>
<?php return ob_get_clean(); }

/* ================= 7. LAYOUT + ROUTER ================= */
function layout(string $title, string $content): void { ?>
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<script>document.documentElement.classList.add('js');</script>
<title><?= e($title) ?> — <?= e(SITE_NAME) ?></title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;color:#f2eefb;min-height:100vh;display:flex;flex-direction:column;
 background:linear-gradient(-45deg,#1a0b2e,#2d1150,#0d1b3e,#3b0f3f);background-size:400% 400%;
 animation:gradMove 16s ease infinite;overflow-x:hidden}
@keyframes gradMove{0%{background-position:0 50%}50%{background-position:100% 50%}100%{background-position:0 50%}}
.blob{position:fixed;border-radius:50%;filter:blur(100px);opacity:.30;z-index:0;pointer-events:none;animation:blob 20s ease-in-out infinite alternate}
.b1{width:420px;height:420px;background:#ff4d94;top:-120px;left:-120px}
.b2{width:380px;height:380px;background:#7b2ff7;bottom:-100px;right:-80px;animation-delay:-6s}
.b3{width:300px;height:300px;background:#00c6ff;top:40%;left:60%;animation-delay:-12s}
@keyframes blob{0%{transform:translate(0,0) scale(1)}50%{transform:translate(60px,-40px) scale(1.15)}100%{transform:translate(-40px,50px) scale(.9)}}
#particles{position:absolute;inset:0;overflow:hidden;pointer-events:none}
.particle{position:absolute;bottom:-12px;border-radius:50%;background:linear-gradient(#ff4d94,#00e5ff);animation:floatUp linear infinite}
@keyframes floatUp{to{transform:translateY(-110vh) rotate(360deg);opacity:0}}
a{color:#ff9ec7;text-decoration:none}
.nav{display:flex;justify-content:space-between;align-items:center;padding:14px 26px;flex-wrap:wrap;gap:8px;
 background:rgba(15,8,35,.75);backdrop-filter:blur(14px);box-shadow:0 2px 16px rgba(0,0,0,.4);position:sticky;top:0;z-index:99}
.logo{font-weight:800;color:#fff;font-size:1.2rem}
.links a{margin-left:13px;color:#d9cdf0;font-size:.95rem}
.links a:hover{color:#ff9ec7}
.pill{background:linear-gradient(90deg,#ff4d94,#b967ff);color:#fff!important;padding:7px 16px;border-radius:20px;font-weight:700}
.badge{display:inline-block;min-width:20px;background:#ff4d6d;color:#fff;font-size:.72rem;font-weight:800;
 padding:2px 6px;border-radius:10px;margin-left:4px;vertical-align:top}
.wrap{max-width:1100px;margin:0 auto;padding:30px 18px;flex:1;width:100%;position:relative;z-index:1}
h1{margin:10px 0 18px;font-size:2.2rem}h2{margin:26px 0 16px;border-left:4px solid #ff4d94;padding-left:12px}
.hero{text-align:center;padding:60px 18px;position:relative}
.avatar{width:110px;height:110px;margin:0 auto 18px;border-radius:50%;display:flex;align-items:center;justify-content:center;
 font-size:56px;background:linear-gradient(135deg,#ff4d94,#7b2ff7);box-shadow:0 0 40px rgba(255,77,148,.6);animation:pulse 3s ease infinite}
.avatar.big{width:150px;height:150px;font-size:76px}
@keyframes pulse{0%,100%{box-shadow:0 0 30px rgba(255,77,148,.5)}50%{box-shadow:0 0 60px rgba(0,229,255,.7)}}
.grad{background:linear-gradient(90deg,#ff4d94,#00e5ff);-webkit-background-clip:text;background-clip:text;color:transparent}
.type-line{font-size:1.35rem;min-height:34px;color:#ffd6ea}.cursor{animation:blink .8s step-end infinite;color:#ff4d94}
@keyframes blink{50%{opacity:0}}
.sub{margin:14px auto 22px;color:#c8bfe6;max-width:640px}
.btn{display:inline-block;background:linear-gradient(90deg,#ff4d94,#b967ff);color:#fff;padding:11px 24px;border-radius:10px;
 font-weight:700;border:none;cursor:pointer;font-size:.98rem;margin:4px;transition:.25s}
.btn:hover{transform:translateY(-3px);box-shadow:0 8px 22px rgba(255,77,148,.45)}
.btn:disabled{opacity:.5;cursor:wait;transform:none}
.btn.alt{background:rgba(255,255,255,.08);border:1.5px solid #00e5ff;color:#8ef1ff}
.btn.small{padding:7px 14px;font-size:.85rem}
.btn.danger{background:linear-gradient(90deg,#ff4d6d,#c9184a);padding:5px 12px;font-size:.8rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:36px}
.stat{background:rgba(255,255,255,.06);backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.13);
 border-radius:14px;text-align:center;padding:18px;transition:.3s}
.stat:hover{transform:translateY(-6px)}
.stat b{font-size:1.5rem;display:block;background:linear-gradient(90deg,#ff4d94,#00e5ff);-webkit-background-clip:text;background-clip:text;color:transparent}
.stat span{color:#c8bfe6;font-size:.85rem}
.glass{background:rgba(255,255,255,.06);backdrop-filter:blur(14px);border:1px solid rgba(255,255,255,.13);border-radius:16px}
.pad{padding:22px}.center{text-align:center}
.split{display:grid;grid-template-columns:1fr 1fr;gap:18px;align-items:start}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:18px}
.card{padding:18px;transition:.3s;overflow:hidden}
.card:hover{transform:translateY(-7px);box-shadow:0 14px 34px rgba(123,47,247,.35)}
.card img{width:100%;height:160px;object-fit:cover;border-radius:10px;margin-bottom:10px}
.card h3{margin-bottom:6px}.card p{color:#c8bfe6;font-size:.92rem}
.tag{color:#ff9ec7;font-size:.82rem;font-weight:700}
.big{font-size:52px;margin-bottom:8px}.fam-emoji{font-size:56px;margin-bottom:6px}
.chartbox{padding:24px}.chartbox canvas{max-height:340px}
.bar-row{margin-bottom:14px}.bar{height:12px;background:rgba(255,255,255,.1);border-radius:6px;overflow:hidden;margin-top:5px}
.bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,#ff4d94,#00e5ff);border-radius:6px;animation:grow 1.4s ease forwards}
@keyframes grow{to{width:var(--w)}}
.muted{color:#a99cc9}.small{font-size:.85rem}
.cover{width:100%;max-height:380px;object-fit:cover;border-radius:14px;margin-bottom:16px}
.article{line-height:1.8;color:#e6defa}
.lock{text-align:center;padding:34px;margin-top:18px;border:1.5px dashed #ff4d94;border-radius:16px;background:rgba(255,77,148,.07)}
video{width:100%;max-width:760px;border-radius:12px;background:#000;margin-top:10px}
form label{display:block;margin:11px 0 5px;font-size:.87rem;color:#c8bfe6}
input,textarea{width:100%;padding:11px;border:1px solid rgba(255,255,255,.18);border-radius:9px;
 background:rgba(10,5,25,.55);color:#fff;font-family:inherit}
textarea{min-height:110px;resize:vertical}
form .btn{margin-top:15px}
.formcard{max-width:430px;margin:26px auto}
canvas#snake{background:#120b24;border-radius:12px;max-width:100%;border:2px solid rgba(255,255,255,.15)}
.pad-controls{margin:10px 0;display:flex;flex-direction:column;align-items:center;gap:6px}
.pad-btn{width:52px;height:40px;border-radius:9px;border:none;background:rgba(255,255,255,.12);color:#fff;font-size:16px;cursor:pointer}
.pad-btn:hover{background:#ff4d94}
.qbtn{display:block;width:100%;margin:8px 0;padding:12px;border-radius:10px;border:1px solid rgba(255,255,255,.2);
 background:rgba(255,255,255,.07);color:#fff;cursor:pointer;font-size:.95rem;text-align:left;transition:.2s}
.qbtn:hover{background:#ff4d94;transform:translateX(5px)}
.board li{padding:7px 0;border-bottom:1px dashed rgba(255,255,255,.12);list-style-position:inside}
.chat{display:flex;gap:16px;margin-top:12px}
.users{width:220px;padding:14px}
.users a{display:flex;justify-content:space-between;align-items:center;padding:9px 11px;border-radius:8px;color:#d9cdf0;margin-top:4px}
.users a.on,.users a:hover{background:linear-gradient(90deg,#ff4d94,#b967ff);color:#fff}
.ubadge{background:#ff4d6d;color:#fff;font-size:.72rem;font-weight:800;padding:2px 7px;border-radius:10px}
.chatbox{flex:1;display:flex;flex-direction:column;height:62vh}
#msgs{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:9px}
.msg{max-width:72%;padding:9px 14px;border-radius:14px;font-size:.94rem;white-space:pre-wrap;word-wrap:break-word;animation:popIn .2s ease}
@keyframes popIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}
.msg.me{align-self:flex-end;background:linear-gradient(90deg,#ff4d94,#b967ff);color:#fff;border-bottom-right-radius:4px}
.msg.them{align-self:flex-start;background:rgba(255,255,255,.12);border-bottom-left-radius:4px}
.msg .t{display:block;font-size:.68rem;opacity:.7;margin-top:3px}
.cinput{display:flex;gap:8px;padding:11px;border-top:1px solid rgba(255,255,255,.13)}
.cinput .btn{margin:0;padding:10px 18px}
table{width:100%;border-collapse:collapse;padding:0;margin-bottom:8px}
th,td{padding:11px 13px;text-align:left;border-bottom:1px solid rgba(255,255,255,.1)}
th{color:#ff9ec7}
.timeline{position:relative;padding-left:30px}
.tl{display:flex;gap:14px;margin-bottom:20px;position:relative}
.tl::before{content:'';position:absolute;left:11px;top:34px;bottom:-22px;width:2px;background:linear-gradient(#ff4d94,#00e5ff)}
.tl:last-child::before{display:none}
.tl span{font-size:26px;z-index:1}
.tl b{color:#ff9ec7}
.about-photo{text-align:center}
/* ✅ FIXED: content only hidden when JS is active — never blank again */
.reveal{transition:opacity .8s ease,transform .8s ease}
.js .reveal{opacity:0;transform:translateY(34px)}
.js .reveal.show{opacity:1;transform:none}
.ft{text-align:center;padding:18px;color:#9a8cc0;background:rgba(15,8,35,.7);font-size:.9rem;margin-top:auto;position:relative;z-index:1}
@media(max-width:800px){.split{grid-template-columns:1fr}.chat{flex-direction:column}.users{width:100%}}
</style></head><body>
<div class="blob b1"></div><div class="blob b2"></div><div class="blob b3"></div>
<nav class="nav">
  <a class="logo" href="?page=home">💜 Soline</a>
  <div class="links">
    <a href="?page=home">Home</a><a href="?page=about">About</a><a href="?page=blog">Blog</a>
    <a href="?page=gallery">Gallery</a><a href="?page=videos">Videos</a><a href="?page=game">🎮 Game</a>
    <a href="?page=chat">💬 Chat<span id="unreadBadge" class="badge" style="display:none"></span></a>
    <?php if(isAdmin()): ?><a href="?page=admin">⚙ Admin</a><?php endif; ?>
    <?php if(isLogged()): ?>
      <a href="?page=logout">Logout (<?= e($_SESSION['uname']) ?> <?= isAdmin()?'👑':'👤' ?>)</a>
    <?php else: ?>
      <a href="?page=login">Login</a><a class="pill" href="?page=register">Register</a>
    <?php endif; ?>
  </div>
</nav>
<main class="wrap">
  <?php if(!empty($_SESSION['flash'])){echo '<div class="glass pad" style="margin-bottom:18px;border-left:4px solid #ff4d94">'.e($_SESSION['flash']).'</div>';unset($_SESSION['flash']);} ?>
  <?= $content ?>
</main>
<footer class="ft">© <?= date('Y') ?> Manishimwe Soline — Made with 💜 and PHP · L5SOD, Muhura</footer>
<script>
/* ✅ FIXED: particles — only run if element exists (Home page) */
const pc=document.getElementById('particles');
if(pc){
  for(let i=0;i<45;i++){
    const p=document.createElement('span');p.className='particle';
    const s=3+Math.random()*7;
    p.style.width=s+'px';p.style.height=s+'px';
    p.style.left=Math.random()*100+'%';
    p.style.animationDuration=(7+Math.random()*11)+'s';
    p.style.animationDelay=(Math.random()*12)+'s';
    pc.appendChild(p);
  }
}

/* ✅ FIXED: typing effect — only run if element exists (Home page) */
const tEl=document.getElementById('typed');
if(tEl){
  const phrases=['I love coding 💻','Future Cyber Security Expert 🛡️','Student at L5SOD 🎓','Python 🐍 · React ⚛️ · Machine Learning 🤖'];
  let pi=0,ci=0,del=false;
  (function type(){
    const w=phrases[pi];
    tEl.textContent=w.slice(0,ci);
    if(!del&&ci<w.length){ci++;setTimeout(type,70);}
    else if(!del){del=true;setTimeout(type,1600);}
    else if(ci>0){ci--;setTimeout(type,35);}
    else{del=false;pi=(pi+1)%phrases.length;setTimeout(type,300);}
  })();
}

/* scroll reveal animation */
const io=new IntersectionObserver(
  es=>es.forEach(en=>{if(en.isIntersecting)en.target.classList.add('show');}),
  {threshold:.1}
);
document.querySelectorAll('.reveal').forEach(el=>io.observe(el));

/* ✅ safety net: never leave content invisible */
setTimeout(()=>{
  document.querySelectorAll('.reveal:not(.show)').forEach(el=>{
    if(el.getBoundingClientRect().top<window.innerHeight)el.classList.add('show');
  });
},1200);

/* unread chat badge (all pages) */
async function updateBadge(){
  try{
    const r=await fetch('?page=unread_api');const d=await r.json();
    const b=document.getElementById('unreadBadge');
    if(b){ if(d.n>0){b.style.display='inline-block';b.textContent=d.n;} else b.style.display='none'; }
  }catch(e){}
}
setInterval(updateBadge,8000);updateBadge();
</script>
</body></html>
<?php }

 $allowed=['home','about','blog','post','gallery','videos','game','chat','login','register','admin'];
if(!in_array($page,$allowed,true))$page='home';
 $fn='page_'.$page;
layout(ucfirst($page),$fn());
