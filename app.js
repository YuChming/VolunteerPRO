const util = require("./utils/util.js")
wx.cloud.init()
const db = wx.cloud.database()
//app.js
App({
  globalData: {
    userInfo: null,
    openId: null,
    accountInfo: null
  },

  onLaunch: function () {

    // 展示本地存储能力
    var logs = wx.getStorageSync('logs') || []
    logs.unshift(Date.now())
    wx.setStorageSync('logs', logs)

    // 登录
    wx.login({
      success: res => {
        // 发送 res.code 到后台换取 openId, sessionKey, unionId
      }
    })
    // 获取用户信息
    wx.getSetting({
      success: res => {
        if (res.authSetting['scope.userInfo']) {
          // 已经授权，可以直接调用 getUserInfo 获取头像昵称，不会弹框
          wx.getUserInfo({
            success: res => {
              // 可以将 res 发送给后台解码出 unionId
              this.globalData.userInfo = res.userInfo
              // 获取openId  
              wx.cloud.callFunction({
                name: "getOpenId",
                complete: res => {
                  console.log(res)
                  this.globalData.openId = res.result.openid
                  let openid = res.result.openid
                  //同步Account信息
                  if (openid === null) {
                    console.log("openId unvalid")
                    return null
                  }
                  console.log(openid)

                  let accountDb = db.collection("Accounts")
                  let data;
                  accountDb.where({
                    openid: openid
                  })
                  .count().then(res => {
                    //get num of results first
                    console.log(res)

                    if (res.total == 0) {
                      //if no such account in database
                      data = {
                        contract_Set: [],
                        handle_url: this.globalData.userInfo.avatarUrl,
                        nickname: this.globalData.userInfo.nickName,
                        openid: openid
                      }
                      db.collection("Accounts").add({
                        data: data,
                      })
                      .then(res => {
                        console.log(res)
                      })
                      .catch(console.error)
                      this.globalData.accountInfo = data
                    }
                    else if (res.total == 1) {
                      //correct, get account info
                      accountDb.where({
                        openid: openid
                      })
                      .get().then(res => {
                        console.log(res)
                        data = res.data
                        this.globalData.accountInfo = data
                      })
                    }
                    else {
                      console.log("why so many results?")
                    }
                  })
                }
              })

              // 由于 getUserInfo 是网络请求，可能会在 Page.onLoad 之后才返回
              // 所以此处加入 callback 以防止这种情况
              if (this.userInfoReadyCallback) {
                this.userInfoReadyCallback(res)
              }
            }
          })
        }
      }
    })
  
  }
})