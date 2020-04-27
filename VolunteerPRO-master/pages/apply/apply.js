// pages/apply/apply.js

const app = getApp()

Page({

  /**
   * 页面的初始数据
   */
  data: {
    step: 1,
    title: "",
    content: "",
    peoplenumber: 0,
    contentId: ""
  },

  /**
   * 生命周期函数--监听页面加载
   */
  onLoad: function (options) {
    // 需检查是否授权有 openid，如无需获取
    if (!app.globalData.openid) {
      console.log("no login")
      wx.showModal({
        title: '提示',
        content: '请登录后进行申请',
        showCancel: false,
        success (res) {
          if (res.confirm) {
            wx.navigateBack({
              complete: (res) => {},
            })
          }
        }
      })
    }
  },
  formSubmit: function (e) {
    this.setData({
      step: 2,
      title: e.detail.value.Title,
      content: e.detail.value.Content,
      peoplenumber: e.detail.value.PeopleNumber
    })
    console.log('form发生了submit事件，携带数据为：', e.detail.value)
  },

  Modify: function () {
    this.setData({
      step: 1
    })
  },

  sub2tass: function () {
    // 构造json数组
    var json = {
      title: this.data.title,
      content: this.data.content,
      people_number: this.data.peoplenumber,
      now_signal_number: 0  
    }
    console.log(json)
    // 上传至数据库
    const db = wx.cloud.database()
    db.collection('Contents').add({
      data: json,
      success: res => {
        // 在返回结果中会包含新创建的记录的 _id
        this.setData({
          contentId: res._id,
        })
        wx.showToast({
          title: '新增记录成功',
        })
        console.log('[数据库] [新增记录] 成功，记录 _id: ', res._id)
        this.setData({
          step: 3
        })
      },
      fail: err => {
        wx.showToast({
          icon: 'none',
          title: '新增记录失败'
        })
        console.error('[数据库] [新增记录] 失败：', err)
      }
    })
   },
})