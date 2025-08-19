// migrate.js
import admin from 'firebase-admin';
import { getFirestore } from 'firebase-admin/firestore';
import dotenv from 'dotenv';

dotenv.config();

// --- DÁN TỪ ĐIỂN CŨ CỦA BẠN VÀO ĐÂY ---
const tuDienDoraemon = {
    "cái loa biết đi": "Jaian", "thánh chảnh": "Suneo", "cục nợ quốc dân": "Nobita", "trùm chém gió": "Suneo", "boss ăn vặt": "Doraemon", "siêu nhân gục ngã": "Nobita", "máy phát kẹo": "Doraemon", "ổ bom di động": "Jaian", "thánh phá đồ": "Nobita", "chuyên gia gây họa": "Nobita", "nhà tài trợ nước mắt": "mẹ Nobita", "lò luyện điểm 0": "lớp học của Nobita", "trùm thất tình": "Nobita", "đứa trẻ cuối cùng của mushika": "Micca", "máy ATM biết đi": "Doraemon", "trí tuệ nhân tạo có tâm": "Doraemon", "con tinh tinh": "Jaian", "con khỉ đột": "Jaian", "khỉ đột": "Jaian", "tinh tinh": "Jaian", "con cáo": "Suneo", "cáo": "Suneo", "bạch tuộc": "Noise", "quần dài": "2 con cá trắm đen đc làm ở Pháp rất là mắc tiền (của Suneo)", "mụ phù thủy": "mẹ của Nobita", "tên ngốc hậu hậu": "Nobita", "tên robinson phiền phức": "Nobita", "thiên tài ngủ": "Nobita", "diễn viên suất sắc": "Nobita", "bậc thầy năn nỉ": "Nobita", "thiên tài thắt dây": "Nobita", "tay vua súng": "Nobita", "xe buýt": "Nobita", "xe bus": "Nobita", "mèo máy": "Doraemon", "mỏ nhọn": "Suneo", "lồi rốn": "Jaian", "yên ắng": "nhà Shizuka", "hình tròn": "bánh rán dorayaki", "kẻ tham lam": "Jaian", "hai người nổi tiếng ham ăn": "Jaian và Suneo", "điểm đen": "điểm 0", "bàn tay vàng trong làng ngáo ngơ": "Nobita", "cục tạ quốc dân": "Nobita", "đại ca sân trường": "Jaian", "người mẫu sừng sỏ": "Suneo", "cô gái tắm mỗi tập": "Shizuka", "vua bánh rán": "Doraemon", "thánh cầu cứu": "Nobita", "người đến từ tương lai": "Doraemon", "cây ATM sống": "Doraemon", "lồng tiếng động đất": "Jaian", "diễn viên chính của bi kịch": "Nobita", "fan cuồng công nghệ": "Suneo", "kẻ lười biếng nhỏ bé": "Nobita", "chồn xanh nhỏ đáng yêu": "Doraemon", "bình yên trước cơn bão": "nhà Shizuka", "cậu bé sáo lạc điệu": "Nobita", "loa phóng thanh biết đi": "Jaian", "trùm phá nốt": "Nobita", "người cứu âm nhạc địa cầu": "Doraemon", "quái vật hút âm": "bào tử noise", "người bạn đến từ hành tinh âm nhạc": "Micca", "thánh phá bản nhạc": "Nobita", "cây sáo truyền thuyết": "cây sáo dọc của mushika", "bản nhạc giải cứu trái đất": "bản giao hưởng địa cầu", "phi công nghiệp dư": "Nobita", "vùng đất trong mơ": "Utopia", "cư dân đám mây": "người sống ở Utopia", "nhà trên trời view đẹp": "Utopia", "người bạn Utopia": "Sonya", "trùm điều khiển thời tiết": "quản lý Utopia", "mặt trăng bay lạc": "Utopia", "chuyến phiêu lưu trên trời": "hành trình của nhóm Nobita", "lâu đài mây thần bí": "trung tâm điều hành Utopia", "trùm chấn động bầu trời": "Suneo lái máy bay", "cậu bé bay không bằng lái": "Nobita", "thánh nhảy moonwalk ngoài vũ trụ": "Nobita", "chuyên gia té không trọng lực": "Nobita", "trạm vũ trụ di động": "tàu của Doraemon", "người bạn tai dài trên mặt trăng": "Luca", "cư dân mặt trăng bí ẩn": "tộc người Espal", "đội thám hiểm mặt trăng": "nhóm Nobita", "mặt trăng giả tưởng": "thế giới do bảo bối tạo ra", "cuộc chiến không trọng lực": "trận đấu trên mặt trăng", "lũ bạn ngoài hành tinh đáng yêu": "Luca và đồng bọn", "bầu trời đêm đầy ảo mộng": "khung cảnh mặt trăng", "cậu bé lười biếng nhất thành phố": "Nobita", "cậu bé xấu tính nhất thành phố": "Jaian", "nhạc sĩ vũ trụ": "Trupet", "nhà soạn nhạc vĩ đại": "Trupet", "người sáng tác giao hưởng địa cầu": "Trupet", "chủ nhân bản giao hưởng địa cầu": "Trupet", "nhà sáng tạo âm nhạc vũ trụ": "Trupet", "nhạc sĩ bảo vệ hòa bình âm nhạc": "Trupet", "rùa siêu tốc vũ trụ": "Moto", "rùa vũ trụ có mai thép": "Moto", "rùa siêu bền": "Moto", "tốc độ vũ trụ từ mai rùa": "Moto", "vũ trụ đua rùa": "Moto", "con rùa nhanh nhất trong không gian": "Moto", "viên đạn của đại bác không khí": "Moto"
};

async function migrate() {
    console.log('Bắt đầu kết nối tới Firebase...');
    const serviceAccountKeyString = process.env.FIREBASE_SERVICE_ACCOUNT_KEY;
    if (!serviceAccountKeyString) {
        console.error('Lỗi: FIREBASE_SERVICE_ACCOUNT_KEY chưa được đặt!');
        return;
    }
    const serviceAccount = JSON.parse(serviceAccountKeyString);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    const db = getFirestore();
    console.log('Kết nối Firebase thành công.');

    const batch = db.batch();
    const dictionaryRef = db.collection('dictionary');

    console.log('Chuẩn bị ghi dữ liệu...');
    Object.entries(tuDienDoraemon).forEach(([key, value]) => {
        const docRef = dictionaryRef.doc(); // Tạo doc mới với ID tự động
        batch.set(docRef, { key, value });
    });

    await batch.commit();
    console.log(`Hoàn tất! Đã di chuyển thành công ${Object.keys(tuDienDoraemon).length} mục vào collection 'dictionary'.`);
}

migrate().catch(console.error);
