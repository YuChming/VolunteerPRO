wx.cloud.init()
const db = wx.cloud.database()
const app = getApp()

const formatTime = date => {
  const year = date.getFullYear()
  const month = date.getMonth() + 1
  const day = date.getDate()
  const hour = date.getHours()
  const minute = date.getMinutes()
  const second = date.getSeconds()

  return [year, month, day].map(formatNumber).join('/') + ' ' + [hour, minute, second].map(formatNumber).join(':')
}

const formatNumber = n => {
  n = n.toString()
  return n[1] ? n : '0' + n
}

function getAccountInfo (openid, that) {
  if(openid === null){
    console.log("openId unvalid")
    return null
  }
  console.log(openid)

  var accountDb = db.collection("Accounts")
  let data
  accountDb.where({
    openid : openid
  })
  .count().then(res => {
    //get num of results first
    console.log(res)
    
    if (res.total == 0) {
      //if no such account in database
      data = {
        contract_Set: [],
        handle_url: app.globalData.userInfo.avatarUrl,
        nickname: app.globalData.userInfo.nickName,
        openid: openid
      }
      db.collection("Accounts").add({
        data: data,
      })
      .then(res => {
        console.log(res)
      })
      .catch(console.error)
      that.accountInfo = data
    }
    else if(res.total == 1){
      //correct, get account info
      accountDb.where({
        openid: openid
      })
      .get().then(res => {
        console.log(res)
        data = res.data
        that.accountInfo = data
      })
    }
    else{
      console.log("why so many results?")
    }
  })
  
  return data
}

module.exports = {
  formatTime: formatTime,
  getAccountInfo: getAccountInfo
}
